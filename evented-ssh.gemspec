require File.expand_path('../lib/evented-ssh/version', __FILE__)
require 'rubygems'

::Gem::Specification.new do |s|
    s.name                      = 'evented-ssh'
    s.version                   = ESSH::VERSION
    s.platform                  = ::Gem::Platform::RUBY
    s.authors                   = ['Stephen von Takach']
    s.email                     = ['steve@aca.im']
    s.homepage                  = 'http://github.com/acaprojects/evented-ssh'
    s.summary                   = 'SSH on event driven IO'
    s.description               = 'SSH on the Ruby platform using event driven IO'
    s.required_rubygems_version = '>= 1.3.6'
    s.files                     = Dir['lib/**/*.rb', '*.md']
    s.require_paths             = ['lib']
    s.license                   = 'MIT'

    s.add_dependency 'net-ssh',   '~> 4.1'
    s.add_dependency 'ipaddress', '~> 0.8'
    s.add_dependency 'libuv',     '>= 3.2.2', '< 5'
end
