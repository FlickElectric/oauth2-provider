require 'active_record'

module OAuth2
  module Model
    autoload :Helpers,       ROOT + '/oauth2/model/helpers'
    autoload :ClientOwner,   ROOT + '/oauth2/model/client_owner'
    autoload :ResourceOwner, ROOT + '/oauth2/model/resource_owner'
    autoload :Hashing,       ROOT + '/oauth2/model/hashing'
    autoload :Authorization, ROOT + '/oauth2/model/authorization'
    autoload :Client,        ROOT + '/oauth2/model/client'

    Schema = OAuth2::Schema

    def self.duplicate_record_error?(error)
      error.class.name == 'ActiveRecord::RecordNotUnique'
    end
  end
end
