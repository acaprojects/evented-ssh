
require 'net/ssh/connection/session'

module Net; module SSH; module Connection
    class Session
        alias_method :original_initialize, :initialize
        def initialize(transport, options = {})
            original_initialize(transport, options)

            # This processes the incoming packets
            # Replacing the IO select calls
            # Next tick so we don't block the current fiber
            transport.reactor.next_tick {
                set_message_dispatcher
            }
        end

        # Dispatch messages as they come in from the transport stream
        # We process them all in a next tick block incase they block on
        # a coroutine. We don't want to stop processing the packets
        def set_message_dispatcher
            @transport.socket.do_process_packet do |packet|
                @transport.reactor.next_tick {
                    unless MAP.key?(packet.type)
                        warn { "unexpected response #{packet.type} (#{packet.inspect})" }
                    end
                    send(MAP[packet.type], packet)
                }
            end
        end

        # This allows the loop function to work as expected
        def dispatch_incoming_packets(raise_disconnect_errors: true)
            @transport.socket.wait_dispatch
        end

        def close
            info { "closing remaining channels (#{channels.length} open)" }
            waiting = channels.collect { |id, channel|
                channel.close
                channel.defer.promise
            }
            begin
                # We use promise resolution here instead of a loop
                ::Libuv.all(waiting).value if channels.any?
            rescue Net::SSH::Disconnect
                raise unless channels.empty?
            end
            transport.close
        end

        # similar to exec! however it returns a promise instead of
        # blocking the flow of execution.
        def p_exec!(command, status: nil)
            status ||= {}
            channel = exec(command, status: status) do |ch, type, data|
                ch[:result] ||= String.new
                ch[:result] << data
            end
            channel.promise.then do
                channel[:result] ||= ""
                channel[:result] &&= channel[:result].force_encoding("UTF-8")

                StringWithExitstatus.new(channel[:result], status[:exit_code])
            end
        end
    end
end; end; end
