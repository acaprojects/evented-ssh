
require 'net/ssh/connection/event_loop'

module Net; module SSH; module Connection
    class EventLoop

        # Same as Net::SSH except it never tries to wait on IO. This
        # basically always blocks the current fiber now until a packet
        # is available. Connection#loop is called in a dedicated fiber
        # who's purpose is to distribute the packets as they come in.
        def process(wait = nil, &block)
            return false unless ev_preprocess(&block)
            #ev_select_and_postprocess(wait)
        end
    end
end; end; end
