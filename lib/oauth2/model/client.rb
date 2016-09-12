module OAuth2
  module Model

    class Client < ActiveRecord::Base
      self.table_name = :oauth2_clients

      belongs_to :oauth2_client_owner, :polymorphic => true
      alias :owner  :oauth2_client_owner
      alias :owner= :oauth2_client_owner=

      has_many :authorizations, :class_name => 'OAuth2::Model::Authorization', :dependent => :destroy

      validates_uniqueness_of :client_id, :name
      validates_presence_of   :name, :redirect_uri
      validate :check_format_of_redirect_uri

      attr_accessible :name, :redirect_uri if (defined?(ActiveRecord::VERSION) && ActiveRecord::VERSION::MAJOR <= 3) || defined?(ProtectedAttributes)

      before_create :generate_credentials

      def self.create_client_id
        Lib::SecureCodeScheme.new.generate(predicate: ->(client_id) {
          Helpers.count(self, :client_id => client_id).zero?
        })
      end

      attr_reader :client_secret

      def client_secret=(secret)
        @client_secret = secret
        hash = BCrypt::Password.create(secret)
        hash.force_encoding('UTF-8') if hash.respond_to?(:force_encoding)
        self.client_secret_hash = hash
      end

      def valid_client_secret?(secret)
        native_app? ? true : BCrypt::Password.new(client_secret_hash) == secret
      end

      def native_app?
        client_type == NATIVE_APP
      end

    private

      def check_format_of_redirect_uri
        uri = URI.parse(redirect_uri)
        errors.add(:redirect_uri, 'must be an absolute URI') unless uri.absolute?
      rescue
        errors.add(:redirect_uri, 'must be a URI')
      end

      def generate_credentials
        self.client_id = self.class.create_client_id
        self.client_secret = OAuth2::Lib::SecureCodeScheme.new.random_string
      end
    end

  end
end
