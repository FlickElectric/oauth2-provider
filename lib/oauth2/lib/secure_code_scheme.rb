module OAuth2

  module Lib

    module SecureCodeScheme

      # Generates a SecureRandom string until the predicate is met
      # (i.e. as long as the code is not already used)
      # There are 2 code gen strategies,
      # - opaque, default, standard SecureRandom string
      # - pkce, for PKCE enabled clients
      # - predicate; a lambda that returns true/false; to test for possible code duplicates
      # e.g
      # code = generate(attributes: {code_type: 'pkce',code_challenge: "", code_challenge_method: "S256"}, predicate: ->() {true})
      def self.generate(attributes: {code_type: OPAQUE}, predicate: )
        generation_method = case attributes[:code_type]
        when OPAQUE
          :random_string
        when PKCE
          :pkce_string
        else  # Shouldn't get here, but assume opaque
          :random_string
        end
        id = nil
        begin
          id = send(generation_method, attributes)
        end until predicate_function(predicate).call(id)
        id
      end

      def self.predicate_function(predicate)
        predicate ? predicate : ->(x) {true}
      end

      # A PKCE code is provided.
      # Decrypt with the base cipher and decode the PKCE string into:
      # - code
      # - method
      def self.pkce_decode_code_and_method(code)
        pkce_code_de_tokenise(pkce_decrypt(code))
      end

      # Take in the verifier that created the code challenge, and the method (usually S256)
      # and produce the original code challenge
      def self.pkce_run_hash_on_verifier(verifier, method = "S256")
        Base64.urlsafe_encode64(Digest::SHA256.digest(verifier)).chomp("=")
      end


      # Decrypt the auth code originally sent to the relying party
      def self.pkce_decrypt(code)
        cipher = aes_cipher(:decrypt)
        begin
          cipher.update(Base64.urlsafe_decode64(code)) + cipher.final
        rescue OpenSSL::Cipher::CipherError => e
          [nil, nil]
        end
      end


      def self.random_string(attributes = {})
        SecureRandom.hex(TOKEN_SIZE / 8).to_i(16).to_s(36)
      end

      def self.pkce_string(attributes)
        cipher = aes_cipher(:encrypt)
        Base64.urlsafe_encode64(cipher.update(pkce_tokenise(attributes[CODE_CHALLENGE.to_sym], attributes[CODE_CHALLENGE_METHOD.to_sym])) + cipher.final)
      end

      def self.aes_cipher(direction)
        cipher = OpenSSL::Cipher::AES.new(256, :CBC)
        cipher.send(direction)
        cipher.key  = ENV[CIPHER_KEY] || raise("Missing '#{CIPHER_KEY}' environment variable.")
        cipher.iv   = ENV[CIPHER_IV]  || raise("Missing '#{CIPHER_IV}' environment variable.")
        cipher
      end

      def self.pkce_tokenise(challenge, method)
        "#{challenge}:#{method}"
      end

      def self.pkce_code_de_tokenise(string)
        string.split(":")
      end

      def self.hashify(token)
        return nil unless String === token
        Digest::SHA1.hexdigest(token)
      end

      def self.generate_id_token(user)
        JSON::JWT.new(generate_id_token_hash(user)).sign(rsa_key(ENV[PRIVATE_KEY]), JWT_ALG).to_s
      end

      def self.rsa_key(key)
        OpenSSL::PKey::RSA.new(key)
      end

      def self.generate_id_token_hash(user)
      {
        # REQUIRED. Issuer Identifier for the Issuer of the response. The iss
        # value is a case sensitive URL using the https scheme that contains
        # scheme, host, and optionally, port number and path components and no
        # query or fragment components.
        iss: Provider.issuer,
        # REQUIRED. Subject Identifier. A locally unique and never reassigned
        # identifier within the Issuer for the End-User, which is intended to be
        # consumed by the Client, e.g., 24400320 or
        # AItOawmwtWwcT0k51BayewNvutrJUqsvl6qs7A4. It MUST NOT exceed 255 ASCII
        # characters in length. The sub value is a case sensitive string.
        sub: user.id,
        # REQUIRED. Audience(s) that this ID Token is intended for. It MUST
        # contain the OAuth 2.0 client_id of the Relying Party as an audience
        # value. It MAY also contain identifiers for other audiences. In the
        # general case, the aud value is an array of case sensitive strings. In
        # the common special case when there is one audience, the aud value MAY be
        # a single case sensitive string.
        aud: Provider.aud,
        # REQUIRED. Expiration time on or after which the ID Token MUST NOT be
        # accepted for processing. The processing of this parameter requires that
        # the current date/time MUST be before the expiration date/time listed in
        # the value. Implementers MAY provide for some small leeway, usually no
        # more than a few minutes, to account for clock skew. Its value is a JSON
        # number representing the number of seconds from 1970-01-01T0:0:0Z as
        # measured in UTC until the date/time. See RFC 3339 [RFC3339] for details
        # regarding date/times in general and UTC in particular.
        exp: Provider.default_duration.from_now.utc.to_i,
        # OPTIONAL. Authentication Methods References. JSON array of strings that
        # are identifiers for authentication methods used in the authentication.
        # For instance, values might indicate that both password and OTP
        # authentication methods were used. The definition of particular values to
        # be used in the amr Claim is beyond the scope of this specification.
        # Parties using this claim will need to agree upon the meanings of the
        # values used, which may be context-specific. The amr value is an array of
        # case sensitive strings.
        amr: user.guest? ? ['guest'] : [],
        # REQUIRED. Time at which the JWT was issued. Its value is a JSON number
        # representing the number of seconds from 1970-01-01T0:0:0Z as measured in
        # UTC until the date/time.
        iat: Time.now.utc.to_i
      }
    end




  end #module

  end  # module

end # module
