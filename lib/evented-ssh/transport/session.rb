require 'ipaddress'

require 'net/ssh/errors'
require 'net/ssh/loggable'
require 'net/ssh/version'
require 'net/ssh/transport/constants'
require 'net/ssh/transport/server_version'
require 'net/ssh/verifiers/null'
require 'net/ssh/verifiers/secure'
require 'net/ssh/verifiers/strict'
require 'net/ssh/verifiers/lenient'

require 'evented-ssh/transport/packet_stream'
require 'evented-ssh/transport/algorithms'

module ESSH; module Transport

    # The transport layer represents the lowest level of the SSH protocol, and
    # implements basic message exchanging and protocol initialization. It will
    # never be instantiated directly (unless you really know what you're about),
    # but will instead be created for you automatically when you create a new
    # SSH session via Net::SSH.start.
    class Session
        include ::Net::SSH::Transport::Constants
        include ::Net::SSH::Loggable

        ServerVersion = Struct.new(:header, :version)

        # The standard port for the SSH protocol.
        DEFAULT_PORT = 22

        # The host to connect to, as given to the constructor.
        attr_reader :host

        # The port number to connect to, as given in the options to the constructor.
        # If no port number was given, this will default to DEFAULT_PORT.
        attr_reader :port

        # The underlying socket object being used to communicate with the remote
        # host.
        attr_reader :socket

        # The ServerVersion instance that encapsulates the negotiated protocol
        # version.
        attr_reader :server_version

        # The Algorithms instance used to perform key exchanges.
        attr_reader :algorithms

        # The host-key verifier object used to verify host keys, to ensure that
        # the connection is not being spoofed.
        attr_reader :host_key_verifier

        # The hash of options that were given to the object at initialization.
        attr_reader :options

        # The event loop that this SSH session is running on
        attr_reader :reactor

        # Instantiates a new transport layer abstraction. This will block until
        # the initial key exchange completes, leaving you with a ready-to-use
        # transport session.
        def initialize(host, **options)
            self.logger = options[:logger]

            @reactor = ::Libuv.reactor

            @host = host
            @port = options[:port] || DEFAULT_PORT
            @bind_address = options[:bind_address] || '0.0.0.0'
            @options = options

            debug { "establishing connection to #{@host}:#{@port}" }

            actual_host = if IPAddress.valid?(@host)
                @host
            else
                @reactor.lookup(@host)[0][0]
            end

            @socket = PacketStream.new(self, **options)
            @socket.connect(actual_host, @port)

            debug { "connection established" }

            @host_key_verifier = select_host_key_verifier(options[:paranoid])
            @algorithms = Algorithms.new(self, options)
            @server_version = ServerVersion.new
            @socket.algorithms = @algorithms

            socket.direct_write "#{::Net::SSH::Transport::ServerVersion::PROTO_VERSION}\r\n"
            socket.start_read

            @algorithms.ready # Wait for this to complete
        end

        def host_keys
            @host_keys ||= begin
                known_hosts = options.fetch(:known_hosts, ::Net::SSH::KnownHosts)
                known_hosts.search_for(options[:host_key_alias] || host_as_string, options)
            end
        end

        # Returns the host (and possibly IP address) in a format compatible with
        # SSH known-host files.
        def host_as_string
            @host_as_string ||= begin
                string = "#{host}"
                string = "[#{string}]:#{port}" if port != DEFAULT_PORT

                peer_ip = socket.peer_ip

                if peer_ip != host
                    string2 = peer_ip
                    string2 = "[#{string2}]:#{port}" if port != DEFAULT_PORT
                    string << "," << string2
                end

                string
            end
        end

        # Returns true if the underlying socket has been closed.
        def closed?
            socket.closed?
        end

        # Cleans up (see PacketStream#cleanup) and closes the underlying socket.
        def close
            info { "closing connection" }
            socket.shutdown
        end

        # Performs a "hard" shutdown of the connection. In general, this should
        # never be done, but it might be necessary (in a rescue clause, for instance,
        # when the connection needs to close but you don't know the status of the
        # underlying protocol's state).
        def shutdown!
            error { "forcing connection closed" }
            socket.close
        end

        # Returns a new service_request packet for the given service name, ready
        # for sending to the server.
        def service_request(service)
            ::Net::SSH::Buffer.from(:byte, SERVICE_REQUEST, :string, service)
        end

        # Requests a rekey operation, and blocks until the operation completes.
        # If a rekey is already pending, this returns immediately, having no
        # effect.
        def rekey!
            if !algorithms.pending?
                algorithms.rekey!
                @algorithms.pending?&.promise&.value # Wait for this to complete
            end
        end

        # Returns immediately if a rekey is already in process. Otherwise, if a
        # rekey is needed (as indicated by the socket, see PacketStream#if_needs_rekey?)
        # one is performed, causing this method to block until it completes.
        def rekey_as_needed
            return if algorithms.pending?
            socket.if_needs_rekey? { rekey! }
        end

        # Returns a hash of information about the peer (remote) side of the socket,
        # including :ip, :port, :host, and :canonized (see #host_as_string).
        def peer
            @peer ||= { ip: socket.peer_ip, port: @port.to_i, host: @host, canonized: host_as_string }
        end

        # Blocks until a new packet is available to be read, and returns that
        # packet. See #poll_message.
        def next_message
            socket.get_packet
        end

        def poll_message
            socket.get_packet
        end

        # Adds the given packet to the packet queue. If the queue is non-empty,
        # #poll_message will return packets from the queue in the order they
        # were received.
        def push(packet)
            socket.queue_packet(packet)
            process_waiting
        end

        # Sends the given message via the packet stream, blocking until the
        # entire message has been sent.
        def send_message(message)
            socket.enqueue_packet(message)
        end

        # Enqueues the given message, such that it will be sent at the earliest
        # opportunity. This does not block, but returns immediately.
        def enqueue_message(message)
            socket.enqueue_packet(message)
        end

        # Configure's the packet stream's client state with the given set of
        # options. This is typically used to define the cipher, compression, and
        # hmac algorithms to use when sending packets to the server.
        def configure_client(options={})
            socket.client.set(options)
        end

        # Configure's the packet stream's server state with the given set of
        # options. This is typically used to define the cipher, compression, and
        # hmac algorithms to use when reading packets from the server.
        def configure_server(options={})
            socket.server.set(options)
        end

        # Sets a new hint for the packet stream, which the packet stream may use
        # to change its behavior. (See PacketStream#hints).
        def hint(which, value=true)
            socket.hints[which] = value
        end

        private

        # Instantiates a new host-key verification class, based on the value of
        # the parameter. When true or nil, the default Lenient verifier is
        # returned. If it is false, the Null verifier is returned, and if it is
        # :very, the Strict verifier is returned. If it is :secure, the even more
        # strict Secure verifier is returned. If the argument happens to respond
        # to :verify, it is returned directly. Otherwise, an exception
        # is raised.
        def select_host_key_verifier(paranoid)
            case paranoid
            when true, nil
                ::Net::SSH::Verifiers::Lenient.new
            when false
                ::Net::SSH::Verifiers::Null.new
            when :very
                ::Net::SSH::Verifiers::Strict.new
            when :secure
                ::Net::SSH::Verifiers::Secure.new
            else
                if paranoid.respond_to?(:verify)
                    paranoid
                else
                    raise ArgumentError, "argument to :paranoid is not valid: #{paranoid.inspect}"
                end
            end
        end
    end
end; end
