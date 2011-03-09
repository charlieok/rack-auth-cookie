$:.push File.expand_path("../lib", __FILE__)
require 'rack/auth/cookie'

Gem::Specification.new do |gem|
  gem.name        = 'rack-auth-cookie'
  gem.version     = Rack::Auth::Cookie::VERSION
  gem.authors     = ["Daniel Berger", "Charlie O'Keefe"]
  gem.email       = ["dberger@globe.gov", "cokeefe@globe.gov"]
  gem.homepage    = 'http://www.github.com/charlieok/rack-auth-cookie'
  gem.summary     = 'A Rack library that authenticates requests using a cookie'
  gem.test_files  = `git ls-files -- test/*`.split("\n")
  gem.files       = `git ls-files`.split("\n")

  gem.extra_rdoc_files = ['CHANGES', 'README', 'MANIFEST']

  gem.add_dependency('rack', '>= 1.0.0')
  gem.add_dependency('json')

  gem.add_development_dependency('test-unit')

  gem.description = <<-EOF
    The rack-auth-cookie library provides a Rack middleware interface for
    authenticating users using a cookie
  EOF
end
