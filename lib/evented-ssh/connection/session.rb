
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
                loop
            }
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
    end
end; end; end
