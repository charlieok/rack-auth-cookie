require 'rubygems'
require 'bundler'

Gem::Specification.new do |gem|
  gem.name      = 'rack-auth-cookie'
  gem.version   = '0.7.6'
  gem.authors   = ["Daniel Berger", "Charlie O'Keefe"]
  gem.email     = 'cokeefe@globe.gov'
  gem.homepage  = 'http://www.github.com/charlieok/rack-auth-cookie'
  gem.summary   = 'A Rack library that authenticates requests using a cookie'
  gem.test_file = 'test/test_rack_auth_cookie.rb'
  gem.files     = Dir['**/*'].delete_if{ |item| item.include?('git') } 

  gem.extra_rdoc_files = ['CHANGES', 'README', 'MANIFEST']

  gem.add_dependency('rack', '>= 1.0.0')
  gem.add_dependency('json')
  
  gem.description = <<-EOF
    The rack-auth-cookie library provides a Rack middleware interface for
    authenticating users using a cookie
  EOF
end
