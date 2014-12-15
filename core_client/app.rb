#!/usr/bin/ruby
# encoding: ASCII-8BIT 

require "sinatra"
require "sinatra/reloader"
require "slim"

locals = {:author => "Noa", :host => "http://localhost:4567", :default_title => "litescrum"}

get '/' do
  slim :app, :locals=>locals
end
