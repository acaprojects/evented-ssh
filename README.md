# Evented SSH

evented-ssh is a net-ssh adapter for Libuv. For the most part you can take any net-ssh code you have and run it in the Libuv reactor.

It runs almost entirely on net-ssh code, replacing parts of the transport and using futures in place of IO select calls.


## Installation

  gem install evented-ssh

