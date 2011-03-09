require 'rubygems'
require 'bundler/setup'
require 'test/unit'

class TestRackAuthCookie < Test::Unit::TestCase

  def setup
    @app  = 1 # Placeholder
    @env  = 1 # Placeholder
    @rack = Rack::Auth::Cookie.new(@app)
  end

  test "version constant should exist" do
    assert_not_nil Rack::Auth::Cookie::VERSION
  end

  test "constructor basic" do
    assert_nothing_raised{ Rack::Auth::Cookie.new(@app) }
  end

  def teardown
    @rack = nil
  end

end
