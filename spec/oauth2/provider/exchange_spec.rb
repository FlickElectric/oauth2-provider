require 'spec_helper'

describe OAuth2::Provider::Exchange do
  before do
    @client = Factory(:client)
    @alice  = TestApp::User['Alice']
    @bob    = TestApp::User['Bob']
    @authorization = create_authorization(:client => @client, :owner => @bob, :code => 'a_fake_code', :scope => 'foo bar')
    allow(OAuth2::Lib::SecureCodeScheme).to receive(:generate).and_return('random_string')
  end

  let(:exchange) { OAuth2::Provider::Exchange.new(@bob, params) }

  shared_examples_for "validates required parameters" do

    describe "missing grant_type" do
      before { params.delete('client_id') }

      it "is invalid" do
        expect(exchange.error).to eq("invalid_request")
        expect(exchange.error_description).to eq("Missing required parameter client_id")
      end
    end

    describe "with an unknown grant type" do
      before { params['grant_type'] = 'unknown' }

      it "is invalid" do
        expect(exchange.error).to eq("unsupported_grant_type")
        expect(exchange.error_description).to eq("The grant type unknown is not recognized")
      end
    end

    describe "missing client_id" do
      before { params.delete('client_id') }

      it "is invalid" do
        expect(exchange.error).to eq("invalid_request")
        expect(exchange.error_description).to eq("Missing required parameter client_id")
      end
    end

    describe "with an unknown client_id" do
      before { params['client_id'] = "unknown" }

      it "is invalid" do
        expect(exchange.error).to eq("invalid_client")
        expect(exchange.error_description).to eq("Unknown client ID unknown")
      end
    end

    describe "missing client_secret" do
      before { params.delete('client_secret') }

      it "is invalid" do
        expect(exchange.error).to eq("invalid_request")
        expect(exchange.error_description).to eq("Missing required parameter client_secret")
      end
    end

    describe "with a mismatched client_secret" do
      before { params['client_secret'] = "nosoupforyou" }

      it "is invalid" do
        expect(exchange.error).to eq("invalid_client")
        expect(exchange.error_description).to eq("Parameter client_secret does not match")
      end

    end

    describe "with lesser scope than the authorization code represents" do
      before { params['scope'] = nil }

      it "is valid" do
        expect(exchange.error).to be_nil
      end
    end

    describe "with scopes not covered by the authorization code" do
      before { params['scope'] = 'qux' }

      it "is invalid" do
        expect(exchange.error).to eq('invalid_scope')
        expect(exchange.error_description).to eq('The request scope was never granted by the user')
      end
    end

  end  # shared example

  shared_examples_for "valid token request" do

    before do
      allow(OAuth2::Lib::SecureCodeScheme).to receive(:generate).and_return('random_access_token')
    end

    it "is valid" do
      expect(exchange.error).to be_nil
    end

    it "updates the Authorization with tokens" do
      exchange.update_authorization
      authorization.reload
      expect(authorization.code).to be_nil
      expect(authorization.access_token_hash).to eq(OAuth2::Lib::SecureCodeScheme.hashify('random_access_token'))
      expect(authorization.refresh_token).to be_nil
    end

  end # shared example

  describe "using authorization_code grant type" do
    let(:params) { { 'client_id'     => @client.client_id,
                     'client_secret' => @client.client_secret,
                     'grant_type'    => 'authorization_code',
                     'code'          => @authorization.code,
                     'redirect_uri'  => @client.redirect_uri }
                 }

    let(:authorization) { @authorization }

    it_should_behave_like "validates required parameters"

    it_should_behave_like "valid token request"

    describe "missing redirect_uri" do
      before { params.delete('redirect_uri') }

      it "is invalid" do
        expect(exchange.error).to eq("invalid_request")
        expect(exchange.error_description).to eq("Missing required parameter redirect_uri")
      end
    end

    describe "with a mismatched redirect_uri" do
      before { params['redirect_uri'] = "http://songkick.com" }

      it "is invalid" do
        expect(exchange.error).to eq("redirect_uri_mismatch")
        expect(exchange.error_description).to eq("Parameter redirect_uri does not match registered URI")
      end

      describe "when the client has not registered a redirect_uri" do
        before { @client.update_attribute(:redirect_uri, nil) }

        it "is valid" do
          exchange.error.should be_nil
        end
      end
    end

    describe "missing code" do
      before { params.delete('code') }

      it "is invalid" do
        expect(exchange.error).to eq("invalid_request")
        expect(exchange.error_description).to eq("Missing required parameter code")
      end
    end

    describe "with an unknown code" do
      before { params['code'] = "unknown" }

      it "is invalid" do
        expect(exchange.error).to eq("invalid_grant")
        expect(exchange.error_description).to eq("The access grant you supplied is invalid")
      end
    end

    describe "with an expired code" do
      before { @authorization.update_attribute(:expires_at, 1.day.ago) }

      it "is invalid" do
        expect(exchange.error).to eq("invalid_grant")
        expect(exchange.error_description).to eq("The access grant you supplied is invalid")
      end
    end
  end

  describe "using password grant type" do
    let(:params) { { 'client_id'      => @client.client_id,
                     'client_secret'  => @client.client_secret,
                     'grant_type'     => 'password',
                     'password'       => 'soldier' }
                 }

    before do
      OAuth2::Provider.handle_passwords do |client, username, password, scopes|
        user = TestApp::User[username]
        if password == 'soldier'
          user.grant_access!(client, :scopes => scopes.reject { |s| s == 'qux' })
        else
          nil
        end
      end
    end

    describe "for a user with existing authorization" do
      let(:authorization) { @authorization }
      before { params['username'] = 'Bob' }

      it_should_behave_like "validates required parameters"
      it_should_behave_like "valid token request"

      describe "missing username" do
        before { params.delete('username') }

        it "is invalid" do
          expect(exchange.error).to eq('invalid_request')
          expect(exchange.error_description).to eq('Missing required parameter username')
        end
      end

      describe "missing password" do
        before { params.delete('password') }

        it "is invalid" do
          expect(exchange.error).to eq('invalid_request')
          expect(exchange.error_description).to eq('Missing required parameter password')
        end
      end

      describe "with a bad password" do
        before { params['password'] = 'bad' }

        it "is invalid" do
          expect(exchange.error).to eq('invalid_grant')
          expect(exchange.error_description).to eq('The access grant you supplied is invalid')
        end
      end
    end

  #   describe "for a user with no existing authorization" do
  #     let(:authorization) { OAuth2::Model::Authorization.find_by_oauth2_resource_owner_id(@alice.id) }
  #
  #     before { params['username'] = 'Alice' }
  #
  #     it_should_behave_like "validates required parameters"
  #     it_should_behave_like "valid token request"
  #
  #     describe "with ungranted but permissible scopes" do
  #       before { params['scope'] = 'lol' }
  #       it_should_behave_like "validates required parameters"
  #       it_should_behave_like "valid token request"
  #
  #       it "sets the scope from the request" do
  #         exchange.update_authorization
  #         authorization.reload
  #         expect(authorization.scopes).to eq(Set.new(['lol']))
  #       end
  #     end
  #   end

end # describe user password grant

  describe "using assertion grant type" do
    let(:params) { { 'client_id'      => @client.client_id,
                     'client_secret'  => @client.client_secret,
                     'grant_type'     => 'assertion',
                     'assertion_type' => 'https://graph.facebook.com/me',
                     'assertion'      => 'Bob' }
                 }

    let(:authorization) { @authorization }

    before do
      OAuth2::Provider.filter_assertions { |client| @client == client }

      OAuth2::Provider.handle_assertions('https://graph.facebook.com/me') do |client, assertion|
        user = TestApp::User[assertion]
        user.grant_access!(client, :scopes => ['foo', 'bar'])
      end
    end

    after do
      OAuth2::Provider.clear_assertion_handlers!
    end

    it_should_behave_like "validates required parameters"
    it_should_behave_like "valid token request"

    describe "missing assertion_type" do
      before { params.delete('assertion_type') }

      it "is invalid" do
        expect(exchange.error).to eq('invalid_request')
        expect(exchange.error_description).to eq('Missing required parameter assertion_type')
      end
    end

    describe "with a non-URI assertion_type" do
      before { params['assertion_type'] = 'invalid' }

      it "is invalid" do
        expect(exchange.error).to eq('invalid_request')
        expect(exchange.error_description).to eq('Parameter assertion_type must be an absolute URI')
      end
    end

    describe "missing assertion" do
      before { params.delete('assertion') }

      it "is invalid" do
        expect(exchange.error).to eq('invalid_request')
        expect(exchange.error_description).to eq('Missing required parameter assertion')
      end
    end

    describe "with an unrecognized assertion_type" do
      before { params['assertion_type'] = 'https://oauth.what.com/ohai' }

      it "is invalid" do
        expect(exchange.error).to eq('unauthorized_client')
        expect(exchange.error_description).to eq('Client cannot use the given assertion type')
      end
    end

    describe "with a client unauthorized to use the assertion scheme" do
      before do
        client = Factory(:client)
        params['client_id'] = client.client_id
        params['client_secret'] = client.client_secret
      end

      it "is invalid" do
        expect(exchange.error).to eq('unauthorized_client')
        expect(exchange.error_description).to eq('Client cannot use the given assertion type')
      end
    end
  end

  describe "using refresh_token grant type" do
    before do
      @refresher = create_authorization(:client => @client,
                                        :owner  => @alice,
                                        :scope  => 'foo bar',
                                        :code   => nil,
                                        :refresh_token => 'roflscale')
    end

    let(:params) { { 'client_id'     => @client.client_id,
                     'client_secret' => @client.client_secret,
                     'grant_type'    => 'refresh_token',
                     'refresh_token' => 'roflscale' }
                 }

    let(:authorization) { @refresher }

    it_should_behave_like "validates required parameters"
    it_should_behave_like "valid token request"

    describe "with unknown refresh_token" do
      before { params['refresh_token'] = 'woops' }

      it "is invalid" do
        expect(exchange.error).to eq("invalid_grant")
        expect(exchange.error_description).to eq("The access grant you supplied is invalid")
      end
    end

  end

  describe "using client_credentials grant type" do
    let(:params) { { 'client_id' => @client.client_id,
                     'client_secret' => @client.client_secret,
                     'grant_type'    => 'client_credentials' }
                 }

    before do
      OAuth2::Provider.handle_client_credentials do |client, owner, scopes|
        owner.grant_access!(client, :scopes => scopes.reject { |s| s == 'qux' })
      end
    end

    let(:authorization) { OAuth2::Model::Authorization.find_by_oauth2_resource_owner_id(@client.owner.id) }

    it_should_behave_like "validates required parameters"
    it_should_behave_like "valid token request"
  end

  describe "using authorization_code grant type for Native App" do
    let(:params) { { 'grant_type'    => 'authorization_code',
                     'code'          => @authorization.code,
                     'code_verifier' => 'a_fake_code_verifier',
                     'redirect_uri'  => @client.redirect_uri, }
                 }

    before do
      @client.update_attribute(:client_type, OAuth2::NATIVE_APP)
      allow(OAuth2::Lib::SecureCodeScheme).to receive(:pkce_run_hash_on_verifier).and_return(@authorization.code)
      allow(OAuth2::Lib::SecureCodeScheme).to receive(:pkce_decrypt).and_return(@authorization.code)
    end

    describe "missing grant_type" do
      before { params.delete('grant_type') }

      it "is invalid" do
        expect(exchange.error).to eq("invalid_request")
        expect(exchange.error_description).to eq("Missing required parameter grant_type")
      end
    end

    describe "missing code" do
      before { params.delete('code') }

      it "is invalid" do
        expect(exchange.error).to eq("invalid_request")
        expect(exchange.error_description).to eq("Missing required parameter client_secret")
      end
    end

    describe "with an unknown grant type" do
      before { params['grant_type'] = 'unknown' }

      it "is invalid" do
        expect(exchange.error).to eq("unsupported_grant_type")
        expect(exchange.error_description).to eq("The grant type unknown is not recognized")
      end
    end

    describe "with client_id" do
      before { params['client_id'] =  @client.client_id }

      it "is valid" do
        expect(exchange.error).to be_nil
      end
    end

    describe "with client_id and no code" do
      before {
        params['client_id'] =  @client.client_id
        params.delete('code')
      }

      it "is invalid" do
        expect(exchange.error).to eq("invalid_request")
        expect(exchange.error_description).to eq("Missing required parameter code")
      end
    end

    describe "with an unknown client_id" do
      before {
        params['client_id'] = "unknown"
        params.delete('code')
      }

      it "is invalid" do
        expect(exchange.error).to eq("invalid_request")
        expect(exchange.error_description).to eq("Missing required parameter client_secret")
      end
    end

    describe "with client_secret" do
      before { params['client_secret'] = @client.client_secret }

      it "is invalid" do
        expect(exchange.error).to eq("invalid_request")
        expect(exchange.error_description).to eq("[:client_secret] must not be provided for native app")
      end
    end

    describe "with lesser scope than the authorization code represents" do
      before { params['scope'] = nil }

      it "is valid" do
        expect(exchange.error).to be_nil
      end
    end

    describe "with scopes not covered by the authorization code" do
      before { params['scope'] = 'qux' }

      it "is invalid" do
        expect(exchange.error).to eq('invalid_scope')
        expect(exchange.error_description).to eq('The request scope was never granted by the user')
      end
    end

  end
end
