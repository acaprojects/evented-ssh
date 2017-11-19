require 'libuv'

require 'net/ssh/errors'
require 'net/ssh/loggable'
require 'net/ssh/transport/constants'
require 'net/ssh/transport/state'
require 'net/ssh/buffer'
require 'net/ssh/packet'

module ESSH; module Transport
    class PacketStream < ::Libuv::TCP
        include ::Net::SSH::Transport::Constants
        include ::Net::SSH::Loggable

        def initialize(session, **options)
            @hints  = {}
            @server = ::Net::SSH::Transport::State.new(self, :server)
            @client = ::Net::SSH::Transport::State.new(self, :client)
            @packet = nil
            @packets = []
            @packets = []
            @pending_packets = []
            @process_pending = nil
            @awaiting = []
            @input = ::Net::SSH::Buffer.new

            @session = session
            @have_header = false

            self.logger = options[:logger]
            super(session.reactor, **options)

            progress { |data| check_packet(data) }
        end

        def prepare(buff)
            progress { |data| check_packet(data) }
            check_packet(buff) unless buff.empty?
            #start_read
        end

        attr_accessor :algorithms

        # The map of "hints" that can be used to modify the behavior of the packet
        # stream. For instance, when authentication succeeds, an "authenticated"
        # hint is set, which is used to determine whether or not to compress the
        # data when using the "delayed" compression algorithm.
        attr_reader :hints

        # The server state object, which encapsulates the algorithms used to interpret
        # packets coming from the server.
        attr_reader :server

        # The client state object, which encapsulates the algorithms used to build
        # packets to send to the server.
        attr_reader :client

        # The name of the client (local) end of the socket, as reported by the
        # socket.
        def client_name
            sockname[0]
        end

        # The IP address of the peer (remote) end of the socket, as reported by
        # the socket.
        def peer_ip
            peername[0]
        end

        # Enqueues a packet to be sent, but does not immediately send the packet.
        # The given payload is pre-processed according to the algorithms specified
        # in the client state (compression, cipher, and hmac).
        def enqueue_packet(payload)
            # try to compress the packet
            payload = client.compress(payload)

            # the length of the packet, minus the padding
            actual_length = 4 + payload.bytesize + 1

            # compute the padding length
            padding_length = client.block_size - (actual_length % client.block_size)
            padding_length += client.block_size if padding_length < 4

            # compute the packet length (sans the length field itself)
            packet_length = payload.bytesize + padding_length + 1

            if packet_length < 16
                padding_length += client.block_size
                packet_length = payload.bytesize + padding_length + 1
            end

            padding = Array.new(padding_length) { rand(256) }.pack("C*")

            unencrypted_data = [packet_length, padding_length, payload, padding].pack("NCA*A*")
            mac = client.hmac.digest([client.sequence_number, unencrypted_data].pack("NA*"))

            encrypted_data = client.update_cipher(unencrypted_data) << client.final_cipher
            message = "#{encrypted_data}#{mac}"

            debug { "queueing packet nr #{client.sequence_number} type #{payload.getbyte(0)} len #{packet_length}" }

            client.increment(packet_length)
            direct_write(message)

            self
        end

        def get_packet(mode = :block)
            case mode
            when :nonblock
                return @packets.shift
            when :block
                packet = @packets.shift
                return packet unless packet.nil?
                defer = @reactor.defer
                @awaiting << defer
                return defer.promise.value
            else
                raise ArgumentError, "expected :block or :nonblock, got #{mode.inspect}"
            end
        rescue
            nil
        end

        def queue_packet(packet)
            pending = @algorithms.pending?
            if not pending
                @packets << packet
            elsif Algorithms.allowed_packet?(packet)
                @packets << packet
            else
                @pending_packets << packet
                if @process_pending.nil?
                    @process_pending = pending
                    @process_pending.promise.finally do
                        @process_pending = nil
                        @packets.concat(@pending_packets)
                        @pending_packets.clear
                        process_waiting
                    end
                end
            end
        end

        def process_waiting
            loop do
                break if @packets.empty?
                waiting = @awaiting.shift
                break unless waiting
                waiting.resolve(@packets.shift)
            end
        end

        # If the IO object requires a rekey operation (as indicated by either its
        # client or server state objects, see State#needs_rekey?), this will
        # yield. Otherwise, this does nothing.
        def if_needs_rekey?
            if client.needs_rekey? || server.needs_rekey?
                yield
                client.reset! if client.needs_rekey?
                server.reset! if server.needs_rekey?
            end
        end

        # Read up to +length+ bytes from the input buffer. If +length+ is nil,
        # all available data is read from the buffer. (See #available.)
        def read_available(length = nil)
            @input.read(length || available)
        end

        # Returns the number of bytes available to be read from the input buffer.
        # (See #read_available.)
        def available
            @input.available
        end

        def read_buffer #:nodoc:
            @input.to_s
        end


        private


        def check_packet(data)
            data.force_encoding(Encoding::BINARY)
            @input.append(data)

            if @have_header
                process_buffer
            else
                version = @input.read_to(/SSH-.+\n/)
                return unless version

                if version.match(/SSH-(1\.99|2\.0)-/)
                    @input = @input.remainder_as_buffer

                    # Grab just the version string (some older implementation don't send the \r char)
                    # This is then used as part of the Diffie-Hellman Key Exchange
                    parts = version.split("\n")
                    @session.server_version.header = parts[0..-2].map { |part| part.chomp }.join("\n")
                    @session.server_version.version = parts[-1].chomp

                    @have_header = true
                    @algorithms.start
                    process_buffer if @input.length > 0
                else
                    reject_and_raise(::Net::SSH::Exception, "incompatible SSH version: #{version}")
                end
            end
        end

        def process_buffer
            packets = []

            # Extract packets from the input stream
            loop do
                packet = next_packet
                break if packet.nil?
                packets << packet
            end

            # Pre-process packets
            packets.each do |packet|
                case packet.type
                when DISCONNECT
                    reject_and_raise(::Net::SSH::Disconnect, "disconnected: #{packet[:description]} (#{packet[:reason_code]})")

                when IGNORE
                    debug { "IGNORE packet received: #{packet[:data].inspect}" }

                when UNIMPLEMENTED
                    lwarn { "UNIMPLEMENTED: #{packet[:number]}" }

                when DEBUG
                    __send__(packet[:always_display] ? :fatal : :debug) { packet[:message] }

                when KEXINIT
                    @algorithms.accept_kexinit(packet)

                else
                    queue_packet(packet)
                end
            end

            # Process what we can
            process_waiting
        end

        def next_packet
            if @packet.nil?
                minimum = server.block_size < 4 ? 4 : server.block_size
                return nil if available < minimum
                data = read_available(minimum)

                # decipher it
                @packet = ::Net::SSH::Buffer.new(server.update_cipher(data))
                @packet_length = @packet.read_long
            end

            need = @packet_length + 4 - server.block_size
            if need % server.block_size != 0
                reject_and_raise(::Net::SSH::Exception, "padding error, need #{need} block #{server.block_size}")
            end

            return nil if available < need + server.hmac.mac_length

            if need > 0
                # read the remainder of the packet and decrypt it.
                data = read_available(need)
                @packet.append(server.update_cipher(data))
            end

            # get the hmac from the tail of the packet (if one exists), and
            # then validate it.
            real_hmac = read_available(server.hmac.mac_length) || ""

            @packet.append(server.final_cipher)
            padding_length = @packet.read_byte

            payload = @packet.read(@packet_length - padding_length - 1)

            my_computed_hmac = server.hmac.digest([server.sequence_number, @packet.content].pack("NA*"))
            if real_hmac != my_computed_hmac
                reject_and_raise(::Net::SSH::Exception, "corrupted mac detected")
            end

            # try to decompress the payload, in case compression is active
            payload = server.decompress(payload)

            debug { "received packet nr #{server.sequence_number} type #{payload.getbyte(0)} len #{@packet_length}" }

            server.increment(@packet_length)
            @packet = nil

            return ::Net::SSH::Packet.new(payload)
        end

        def on_close(pointer)
            super(pointer)
            client.cleanup
            server.cleanup

            @reactor.next_tick do
                reject_reason = @close_error || 'connection closed'
                @awaiting.each do |wait|
                    wait.reject(reject_reason)
                end
                @awaiting.clear
                @algorithms&.reject(reject_reason)
            end
        rescue => e
            error { e }
        end

        def reject_and_raise(klass, msg)
            error = klass.new(msg)
            reject(error)
            raise error
        end
    end
end; end
