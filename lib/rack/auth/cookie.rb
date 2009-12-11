require 'openssl'
require 'rack/request'

module Rack
  module Auth
    class Cookie
      # Creates a new Rack::Auth::Cookie object. The +cookie_name+ param gives the
      # name of the cookie used to authenticate the requestor. The default is
      # 'auth_token'.
      #
      def initialize(app, options = {})
        @app = app
        @@secret = options[:secret]
        @@cookie_name = options[:cookie_name] || "auth_token"
        @@env = {}
      end

      # The call method we've defined first checks to see if AUTH_USER or
      # AUTH_FAIL are set in the environment. If either is set, we assume that
      # the request has already either passed or failed authentication and move on.
      #
      # If neither is set, we check for the cookie with the name we've been
      # configured to use. If present, we attempt to authenticate the user using
      # the cookie. If successful then AUTH_USER is set to the username.
      #
      # If unsuccessful then AUTH_USER is not set and AUTH_FAIL is set to an
      # appropriate error message.
      #
      # It is then up to the application to check for the presence of AUTH_USER
      # and/or AUTH_FAIL and act as necessary.
      #
      def call(env)
        
        # Do not authenticate if either one of these is set
        if env['AUTH_USER'] || env['AUTH_FAIL']
          return @app.call(env)
        end
        
        request = Rack::Request.new(env)
        
        # Only authenticate if there's a cookie in the request named @cookie_name
        unless request.cookies.has_key?(@@cookie_name)
          return @app.call(env)
        end
        
        begin
          # Separate the cookie data and the digest
          cookie_with_digest = request.cookies[@@cookie_name]
          cookie_data, digest = cookie_with_digest.split("--")
          
          # Make sure the cookie hasn't been tampered with
          unless digest == self.class.generate_hmac(cookie_data)
            env['AUTH_FAIL'] = "Invalid cookie digest!"
            return @app.call(env)
          end
          
          # Unpack the cookie data back to a hash
          begin
            cookie_data = cookie_data.unpack("m*").first
            cookie_data = Marshal.load(cookie_data)
          rescue
            env['AUTH_FAIL'] = "Unable to read cookie!"
            return @app.call(env)
          end
          
          # Put the values from the hash into the environment
          env['AUTH_USER'] = cookie_data['AUTH_USER']
          
          env['AUTH_TYPE'] = "Cookie"
        rescue => err
          env.delete('AUTH_USER')
          env['AUTH_FAIL'] = "Unexpected failure during Cookie authentication"
        end
        
        @app.call(env)
      end
      
      def self.cookie_name
        @@cookie_name
      end
      
      def self.create_auth_token(env)
        # Copy relevant auth info for storage in a token
        auth_info = Hash.new
        auth_info['AUTH_USER'] = env['AUTH_USER']
        
        # Pack the auth_info hash for cookie storage
        cookie_data = Marshal.dump(auth_info)
        cookie_data = [cookie_data].pack("m*")
        
        # Add a digest value to cookie_data to prevent tampering
        "#{cookie_data}--#{self.generate_hmac(cookie_data)}"
      end
      
      def self.generate_hmac(data)
        OpenSSL::HMAC.hexdigest(OpenSSL::Digest::SHA1.new, @@secret, data)
      end
    end
  end
end
