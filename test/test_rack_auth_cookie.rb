require 'rubygems'
require 'bundler/setup'

require 'test/unit'
require 'rack/auth/cookie'

class TestRackAuthCookie < Test::Unit::TestCase

  def setup
    @app  = 1 # Placeholder
    @env  = 1 # Placeholder
    @rack = Rack::Auth::Cookie.new(@app)
  end

  def test_version
    assert_equal('0.7.6', Rack::Auth::Cookie::VERSION)
  end

  def test_constructor_basic
    assert_nothing_raised{ Rack::Auth::Cookie.new(@app) }
  end

  def teardown
    @rack = nil
  end
end
