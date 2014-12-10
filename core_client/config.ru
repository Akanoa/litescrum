require "./app"

require 'rack-livereload'

use Rack::LiveReload, :live_relaod_port => 35729
run Sinatra::Application
