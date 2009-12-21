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
        @@idle_timeout = options[:idle_timeout] || 3600
        @@max_lifetime = options[:max_lifetime] || 36000
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
        request = Rack::Request.new(env)
        auth_fail = false
        
        # Only authenticate if there's a cookie in the request named @@cookie_name
        unless request.cookies.has_key?(@@cookie_name)
          return finish(@app, env)
        end
        
        # Get the data from the cookie
        begin
          cookie_value = request.cookies[@@cookie_name]
          hash_data = read_cookie(cookie_value)
        rescue Exception => e
          auth_fail = e.message
        end
        
        # Do not authenticate if either one of these is set
        # This check is done late so that we'll have already
        # checked the cookie
        if env['AUTH_USER'] || env['AUTH_FAIL']
          return finish(@app, env, cookie_value)
        end
        
        if hash_data["AUTH_EXPIRE_DATETIME"] < Time.now.utc
          auth_fail = "Timed out due to inactivity"
        end
        
        if hash_data["AUTH_DATETIME"] + @@max_lifetime < Time.now.utc
          auth_fail = "Maximum session length exceeded"
        end
        
        if auth_fail
          env['AUTH_FAIL'] = auth_fail
        else
          # Put the values from the hash into the environment
          env['AUTH_USER'] = hash_data['AUTH_USER']
          
          env['AUTH_TYPE'] = hash_data['AUTH_TYPE']
          env['AUTH_TYPE_USER'] = hash_data['AUTH_TYPE_USER']
          
          env['AUTH_TYPE_THIS_REQUEST'] = "Cookie"
          
          env['AUTH_DATETIME'] = Time.at(hash_data['AUTH_DATETIME']).utc
          env['AUTH_EXPIRE_DATETIME'] = Time.at(hash_data['AUTH_EXPIRE_DATETIME']).utc
        end
        
        finish(@app, env, cookie_value)
      end
      
      def finish(app, env, cookie_value_from_request = nil)
        status, headers, body = @app.call(env)
        
        # Assume our cookie isn't in the response unless/until we find it
        response_cookie = false
        
        if headers.has_key?("Set-Cookie")
          set_cookie = headers["Set-Cookie"]
          set_cookie_pieces = set_cookie.split(";")
          
          # TODO: parse cookies from header and find @@cookie_name
          set_cookie_pieces.each_with_index do |piece, index|
            if piece[@@cookie_name]
              response_cookie = true
            end
          end
        end
        
        # If the application isn't making any changes to the cookie, we can mess with it
        if cookie_value_from_request && !response_cookie
          cookie = self.class.create_auth_cookie(env)
          
          headers["Set-Cookie"] << cookie
        end
        
        [status, headers, body]
      end
      
      def read_cookie(cookie_value)
        # Separate the cookie data and the digest
        raw_data, digest = cookie_value.split("--")
        
        # Check for evidence of tampering
        unless digest == self.class.generate_hmac(raw_data)
          raise "Invalid cookie digest!"
        end
        
        # Unpack the cookie data back to a hash
        begin
          unpacked_data = raw_data.unpack("m*").first
          hash_data = Marshal.load(unpacked_data)
        rescue
          raise "Unable to read cookie!"
        end
        
        hash_data
      end
      
      def self.cookie_name
        @@cookie_name
      end
      
      def self.create_auth_token(env)
        # Copy relevant auth info for storage in a token
        auth_info = Hash.new
        
        auth_info['AUTH_USER'] = env['AUTH_USER']
        
        auth_info['AUTH_TYPE'] = env['AUTH_TYPE'] || "Unknown"
        auth_info['AUTH_TYPE_USER'] = env['AUTH_TYPE_USER'] || env['AUTH_USER']
        
        # Expecting env['AUTH_DATETIME'] to hold an instance of Time
        if env['AUTH_DATETIME']
          auth_info['AUTH_DATETIME'] = env['AUTH_DATETIME'].to_i
        else
          auth_info['AUTH_DATETIME'] = Time.now.utc.to_i
        end
        
        auth_info['AUTH_EXPIRE_DATETIME'] = Time.now.utc.to_i + @@idle_timeout
        
        # Pack the auth_info hash for cookie storage
        cookie_data = Marshal.dump(auth_info)
        cookie_data = [cookie_data].pack("m*")
        
        # Add a digest value to cookie_data to prevent tampering
        "#{cookie_data}--#{generate_hmac(cookie_data)}"
      end
      
      def self.create_auth_cookie(env)
        cookie_value = create_auth_token(env)
        cookie = "#{@@cookie_name}=#{URI.escape(cookie_value)}; "
        cookie += "domain=.#{top_level_domain(env)}; "
        cookie += "path=/; "
        cookie += "HttpOnly; "
      end
      
      def self.generate_hmac(data)
        OpenSSL::HMAC.hexdigest(OpenSSL::Digest::SHA1.new, @@secret, data)
      end
      
      def self.raw_host_with_port(env)
        if forwarded = env["HTTP_X_FORWARDED_HOST"]
          forwarded.split(/,\s?/).last
        else
          env['HTTP_HOST'] || "#{env['SERVER_NAME'] ||
          env['SERVER_ADDR']}:#{env['SERVER_PORT']}"
        end
      end

      def self.host(env)
        raw_host_with_port(env).sub(/:\d+$/, '')
      end
      
      def self.top_level_domain(env, tld_length = 1)
        host(env).split('.').last(1 + tld_length).join('.')
      end
    end
  end
end
