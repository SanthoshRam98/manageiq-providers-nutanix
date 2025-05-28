class ManageIQ::Providers::Nutanix::InfraManager < ManageIQ::Providers::InfraManager
  require_nested :MetricsCapture
  require_nested :MetricsCollectorWorker
  require_nested :Refresher
  require_nested :RefreshWorker
  require_nested :Vm
  supports :create
  # Form schema for creating/editing a provider, it should follow the DDF specification
  # For more information check the DDF documentation at: https://data-driven-forms.org
  #
  # If for some reason some fields should not be included in the submitted data, there's
  # a `skipSubmit` flag. This is useful for components that provide local-only behavior,
  # like the validate-provider-credentials or protocol-selector.
  #
  # There's validation built on top on these fields in the API, so if some field isn't
  # specified here, the API endpoint won't allow the request to go through.
  # Make sure you don't dot-prefix match any field with any other field, because it can
  # confuse the validation. For example you should not have `x` and `x.y` fields at the
  # same time.
  def self.params_for_create
    {
      :fields => [
        {
          :component => 'sub-form',
          :name      => 'endpoints-subform',
          :title     => _('Endpoints'),
          :fields    => [
            {
              :component              => 'validate-provider-credentials',
              :name                   => 'authentications.default.valid',
              :skipSubmit             => true,
              :validationDependencies => %w[type],
              :fields                 => [
                {
                  :component    => "select",
                  :id           => "endpoints.default.verify_ssl",
                  :name         => "endpoints.default.verify_ssl",
                  :label        => _("SSL verification"),
                  :dataType     => "integer",
                  :isRequired   => true,
                  :validate     => [{:type => "required"}],
                  :initialValue => OpenSSL::SSL::VERIFY_NONE,
                  :options      => [
                    {
                      :label => _('Do not verify'),
                      :value => OpenSSL::SSL::VERIFY_NONE,
                    },
                    {
                      :label => _('Verify'),
                      :value => OpenSSL::SSL::VERIFY_PEER,
                    },
                  ]
                },
                {
                  :component  => "text-field",
                  :name       => "endpoints.default.hostname",
                  :label      => _("Hostname (or IPv4 or IPv6 address)"),
                  :isRequired => true,
                  :validate   => [{:type => "required"}],
                },
                {
                  :component    => "text-field",
                  :name         => "endpoints.default.port",
                  :label        => _("API Port"),
                  :type         => "number",
                  :initialValue => 9440, # Changed to standard Nutanix port
                  :isRequired   => true,
                  :validate     => [{:type => "required"}]
                },
                {
                  :component  => "text-field",
                  :name       => "authentications.default.userid",
                  :label      => "Username",
                  :isRequired => true,
                  :validate   => [{:type => "required"}]
                },
                {
                  :component  => "password-field",
                  :name       => "authentications.default.password",
                  :label      => "Password",
                  :type       => "password",
                  :isRequired => true,
                  :validate   => [{:type => "required"}]
                },
              ]
            }
          ]
        }
      ]
    }
  end


def self.verify_credentials(args)
  endpoint = args.dig("endpoints", "default")
  authentication = args.dig("authentications", "default")

  hostname = endpoint&.dig("hostname")
  port = endpoint&.dig("port")
  verify_ssl = endpoint&.dig("verify_ssl") || OpenSSL::SSL::VERIFY_NONE
  username = authentication&.dig("userid")
  password = ManageIQ::Password.try_decrypt(authentication&.dig("password")) # Decrypt here

  !!raw_connect(hostname, port, username, password, verify_ssl)
rescue => err
  raise MiqException::MiqInvalidCredentialsError, err.message
end

  def verify_credentials(auth_type = nil, options = {})
    begin
      connect
      true
    rescue => err
      raise MiqException::MiqInvalidCredentialsError, err.message
    end
  end

# In ManageIQ::Providers::Nutanix::InfraManager
def connect(options = {})
  raise MiqException::MiqHostError, "No credentials defined" if missing_credentials?(options[:auth_type])

  auth_type = options[:auth_type] || 'default'
  username, password = auth_user_pwd(auth_type)

  # Initialize the API client
  api_client = self.class.raw_connect(
    default_endpoint.hostname,
    default_endpoint.port,
    username,
    password,
    default_endpoint.verify_ssl
  )

  # Return the appropriate service client
  case options[:service]
  when "Infra"
    ConnectionManager.new(api_client) # Return connection manager for infra services
  else
    api_client # Default to base API client
  end
end

  def self.validate_authentication_args(params)
    # return args to be used in raw_connect
    return [params[:default_userid], ManageIQ::Password.encrypt(params[:default_password])]
  end

  def self.hostname_required?
    # TODO: ExtManagementSystem is validating this
    false
  end

  def self.ems_type
    @ems_type ||= "nutanix".freeze
  end

  def self.description
    @description ||= "Nutanix".freeze
  end

  def parent_manager
    nil
  end
  
  # TODO: This class represents a fake Ruby SDK with sample data.
  #       Remove this and use a real Ruby SDK in the raw_connect method
def self.raw_connect(hostname, port, username, password, verify_ssl)
  require "nutanix_vmm"

  # Force-disable SSL verification in development/test
  if Rails.env.development? || Rails.env.test?
    verify_ssl = OpenSSL::SSL::VERIFY_NONE
  end

  verify_ssl_bool = verify_ssl == OpenSSL::SSL::VERIFY_PEER

  config = NutanixVmm::Configuration.new do |c|
    c.host = "#{hostname}:#{port}"
    c.scheme = "https"
    c.username = username
    c.password = password
    c.verify_ssl = verify_ssl_bool
    c.verify_ssl_host = verify_ssl_bool
    c.base_path = "/api"
    
    # # Explicitly disable SSL peer verification at the libcurl level
    # c.ssl_verifypeer = verify_ssl_bool ? 1 : 0  # 0=disable, 1=enable
    # c.ssl_verifyhost = verify_ssl_bool ? 2 : 0  # 0=disable, 2=enable
  end

  api_client = NutanixVmm::ApiClient.new(config)
  connection_manager = ConnectionManager.new(api_client)

  # Test connection
  connection_manager.get_vms

  api_client
rescue => err
  raise MiqException::MiqInvalidCredentialsError, "Authentication failed: #{err.message}"
end


  def self.ems_type
    @ems_type ||= "nutanix".freeze
  end

  def self.description
    @description ||= "Nutanix".freeze
  end

  # ConnectionManager provides access to different API instances
  class ConnectionManager
    attr_reader :api_client

    def initialize(api_client)
      @api_client = api_client
    end

    def vms_api
      @vms_api ||= NutanixVmm::VmApi.new(@api_client)
    end

    def clusters_api
      # Add Cluster API initialization when needed
      # @clusters_api ||= NutanixVmm::ClusterApi.new(@api_client)
    end

    def hosts_api
      # Add Host API initialization when needed
      # @hosts_api ||= NutanixVmm::HostApi.new(@api_client)
    end

    # Test method to verify connection is working
    def get_vms
      vms_api.list_vms_0
    end
  end
end