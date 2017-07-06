require 'net/ssh'

require 'evented-ssh/transport/packet_stream'
require 'evented-ssh/transport/algorithms'
require 'evented-ssh/transport/session'

require 'evented-ssh/connection/channel'
require 'evented-ssh/connection/session'

module ESSH
    VALID_OPTIONS = [
      :auth_methods, :bind_address, :compression, :compression_level, :config,
      :encryption, :forward_agent, :hmac, :host_key, :remote_user,
      :keepalive, :keepalive_interval, :keepalive_maxcount, :kex, :keys, :key_data,
      :languages, :logger, :paranoid, :password, :port, :proxy,
      :rekey_blocks_limit,:rekey_limit, :rekey_packet_limit, :timeout, :verbose,
      :known_hosts, :global_known_hosts_file, :user_known_hosts_file, :host_key_alias,
      :host_name, :user, :properties, :passphrase, :keys_only, :max_pkt_size,
      :max_win_size, :send_env, :use_agent, :number_of_password_prompts,
      :append_all_supported_algorithms, :non_interactive, :password_prompt,
      :agent_socket_factory, :minimum_dh_bits
    ]

    def self.start(host, user = nil, **options, &block)
        invalid_options = options.keys - VALID_OPTIONS
        if invalid_options.any?
            raise ArgumentError, "invalid option(s): #{invalid_options.join(', ')}"
        end

        assign_defaults(options)
        _sanitize_options(options)

        options[:user] = user if user
        options = configuration_for(host, options.fetch(:config, true)).merge(options)
        host = options.fetch(:host_name, host)

        if options[:non_interactive]
            options[:number_of_password_prompts] = 0
        end

        if options[:verbose]
            options[:logger].level = case options[:verbose]
                when Integer then options[:verbose]
                when :debug then Logger::DEBUG
                when :info  then Logger::INFO
                when :warn  then Logger::WARN
                when :error then Logger::ERROR
                when :fatal then Logger::FATAL
                else raise ArgumentError, "can't convert #{options[:verbose].inspect} to any of the Logger level constants"
                end
        end

        transport = Transport::Session.new(host, options)
        auth = ::Net::SSH::Authentication::Session.new(transport, options)

        user = options.fetch(:user, user) || Etc.getlogin
        if auth.authenticate("ssh-connection", user, options[:password])
            connection = ::Net::SSH::Connection::Session.new(transport, options)
            if block_given?
                begin
                    yield connection
                ensure
                    connection.close unless connection.closed?
                end
            else
                return connection
            end
        else
            transport.close
            raise AuthenticationFailed, "Authentication failed for user #{user}@#{host}"
        end
    rescue => e
        transport.socket.__send__(:reject, e) if transport
        raise
    end

    def self.configuration_for(host, use_ssh_config)
        files = case use_ssh_config
            when true then ::Net::SSH::Config.expandable_default_files
            when false, nil then return {}
            else Array(use_ssh_config)
            end

        ::Net::SSH::Config.for(host, files)
    end

    def self.assign_defaults(options)
        if !options[:logger]
            options[:logger] = Logger.new(STDERR)
            options[:logger].level = Logger::FATAL
        end

        options[:password_prompt] ||= ::Net::SSH::Prompt.default(options)

        [:password, :passphrase].each do |key|
            options.delete(key) if options.key?(key) && options[key].nil?
        end
    end

    def self._sanitize_options(options)
        invalid_option_values = [nil,[nil]]
        unless (options.values & invalid_option_values).empty?
            nil_options = options.select { |_k,v| invalid_option_values.include?(v) }.map(&:first)
            Kernel.warn "#{caller_locations(2, 1)[0]}: Passing nil, or [nil] to Net::SSH.start is deprecated for keys: #{nil_options.join(', ')}"
        end
    end
    private_class_method :_sanitize_options
end
