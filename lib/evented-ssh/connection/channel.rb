
require 'net/ssh/connection/channel'

module Net; module SSH; module Connection
    class Channel
        alias_method :original_initialize, :initialize
        def initialize(connection, *args, &block)
            original_initialize(connection, *args, &block)
            @defer = connection.transport.reactor.defer
        end

        attr_reader :defer

        # Use promise resolution instead of a loop
        def wait
            @defer.promise.value
        end

        # Allow direct access to the promise.
        # Means we can do parallel tasks and then grab
        # the results of multiple executions.
        def promise
            @defer.promise
        end

        alias_method :original_do_close, :do_close
        def do_close
            # Resolve the promise and anything waiting
            @defer.resolve(nil)
            original_do_close
        end
    end
end; end; end
