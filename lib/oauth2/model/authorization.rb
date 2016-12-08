module OAuth2

  module Model

    class Authorization < ActiveRecord::Base
      self.table_name = :oauth2_authorizations

      belongs_to :oauth2_resource_owner, :polymorphic => true
      alias :owner  :oauth2_resource_owner
      alias :owner= :oauth2_resource_owner=

      belongs_to :client, :class_name => 'OAuth2::Model::Client'

      validates_presence_of :client, :owner

      validates_uniqueness_of :code,               :scope => :client_id, :allow_nil => true
      validates_uniqueness_of :refresh_token_hash, :scope => :client_id, :allow_nil => true
      validates_uniqueness_of :access_token_hash,                        :allow_nil => true

      attr_accessible nil if (defined?(ActiveRecord::VERSION) && ActiveRecord::VERSION::MAJOR <= 3) || defined?(ProtectedAttributes)

      class << self
        private :create, :new
      end

      extend Hashing
      hashes_attributes :access_token, :refresh_token

      def self.create_code(client: , additional_attributes: {}, predicate: nil)
        Lib::SecureCodeScheme.generate( attributes: code_gen_attributes(additional_attributes),
                                            predicate: predicate)
      end

      # When PKCE Atttributes (https://tools.ietf.org/html/rfc7636) are provided
      # the code generation will use them as apposed to an opaque code
      def self.code_gen_attributes(attr)
        if attr.keys.include? CODE_CHALLENGE
          {code_type: PKCE, code_challenge: attr[CODE_CHALLENGE], code_challenge_method: attr[CODE_CHALLENGE_METHOD]}
        else
          {code_type: OPAQUE}
        end
      end

      def self.create_access_token
        Lib::SecureCodeScheme.generate(predicate: ->(token) {
          hash = Lib::SecureCodeScheme.hashify(token)
          Helpers.count(self, :access_token_hash => hash).zero?
        })
      end

      def self.create_jwt_access_token(user)
        Lib::SecureCodeScheme.generate_id_token(user)
      end

      def self.create_refresh_token(client)
        # OAuth2.generate_id do |refresh_token|
        Lib::SecureCodeScheme.generate(predicate: ->(refresh_token) {
          hash = Lib::SecureCodeScheme.hashify(refresh_token)
          Helpers.count(client.authorizations, :refresh_token_hash => hash).zero?
        })
      end

      def self.for(owner, client, attributes = {})
        return nil unless owner and client

        unless client.is_a?(Client)
          raise ArgumentError, "The argument should be a #{Client}, instead it was a #{client.class}"
        end

        instance = owner.oauth2_authorization_for(client) ||
                   new do |authorization|
                     authorization.owner  = owner
                     authorization.client = client
                   end


        case attributes[RESPONSE_TYPE]
          when CODE
            instance.code ||= create_code(client: client, additional_attributes: attributes , predicate: nil)
          when TOKEN
            instance.access_token  ||= create_access_token
            instance.refresh_token ||= create_refresh_token(client)
          when CODE_AND_TOKEN
            instance.code = create_code(client: client, additional_attributes: attributes, predicate: nil)
            instance.access_token  ||= create_access_token
            instance.refresh_token ||= create_refresh_token(client)
        end

        if attributes[DURATION]
          instance.expires_at = Time.now + attributes[DURATION].to_i
        else
          instance.expires_at = nil
        end

        scopes = instance.scopes + (attributes[SCOPES] || [])
        scopes += attributes[SCOPE].split(/\s+/) if attributes[SCOPE]
        instance.scope = scopes.empty? ? nil : scopes.entries.join(' ')

        instance.save && instance

      rescue Object => error
        if Model.duplicate_record_error?(error)
          retry
        else
          raise error
        end
      end

      # This will only return an authorisation for JWT and non-JWT tokens
      def self.find_by_token_tuple(token_tuple)
        return nil if token_tuple.nil?

        if token_tuple[0] == :jwt
          find_by_jwt(token_tuple[1])
        else
          find_by_access_token_hash(Lib::SecureCodeScheme.hashify(token_tuple[1]))
        end
      end

      def self.find_by_jwt(jwt)
        auth = find_by(id_token: jwt)
        return nil if auth && auth.expired?
        auth
      rescue ActiveRecord::ActiveRecordError => e
        nil
      end

      def exchange!
        self.code          = nil
        self.access_token  = self.class.create_access_token
        self.refresh_token = nil
        save!
      end

      def exchange_for_token!(token_type:)
        self.code          = nil
        self.id_token      = self.class.create_jwt_access_token(owner)
        self.access_token  = self.class.create_access_token
        self.refresh_token = nil
        save!
      end

      def expired?
        return false unless expires_at
        expires_at < Time.now
      end

      def expires_in
        expires_at && (expires_at - Time.now).ceil
      end

      def generate_code(additional_attributes: {}, predicate: )
        # TODO: This is only called once, and the memorisation might effect the resending
        # of failure calls that use varying PKCE codes
        # Also, memorisation is expected in the tests
        if client.native_app?
          self.code = self.class.create_code(client: client, additional_attributes: additional_attributes, predicate: predicate)
        else
          self.code ||= self.class.create_code(client: client, additional_attributes: additional_attributes, predicate: predicate)
        end
        save && code
      end

      def generate_access_token
        self.access_token ||= self.class.create_access_token
        save && access_token
      end

      def grants_access?(user, *scopes)
        not expired? and user == owner and in_scope?(scopes)
      end

      def in_scope?(request_scope)
        [*request_scope].all?(&scopes.method(:include?))
      end

      def scopes
        scopes = scope ? scope.split(/\s+/) : []
        Set.new(scopes)
      end

    end

  end # module

end # module
