#!/usr/bin/ruby
# encoding: ASCII-8BIT 

require "sinatra"
require "sinatra/reloader"
require 'sinatra/formkeeper'
require 'sinatra/advanced_routes'
require "slim"
require "digest"
require "time"
require 'yaml'

require 'mongo'
require 'json'
require 'json/ext' # required for .to_json

require "stylus"
require 'stylus/tilt'


#---------------------------------------------------------
# globals variables
#---------------------------------------------------------

include Mongo

configure do
  conn = MongoClient.new("localhost", 27017)
  set :mongo_connection, conn
  set :mongo_db, conn.db('litescrum')
end

locals = {:author => "Noa", :host => "http://localhost:4567", :default_title => "Api litescrum"}

salt = "}!=zY1RsS-IV{bO?GYK,4h~lhcu[Djh%S$(/=>+0B_onaDA2@S!!@$tsE-s-TTKq"
available_scopes = ["read_only", "core_client"]

#define how many time a token is valid from his creation
lifetime_tokens = {
	:admin_token => (60*60*24*365*1000),#lifetime: 1000 years
	:api_token   => (60*60*24*365),#lifetime: 1 years
	:acces_token => (60*60*3)#lifetime: 3 hours
}

#----------------------------------------------------------
# ****************SCOPE HANDLING***************************
#----------------------------------------------------------

route_exceptions = [
	"POST /auth/register",
	"POST /auth/login",
	"GET /auth/register",
	"GET /auth/login",
	"POST /auth/token/refresh",
	"GET /",
	"GET /routes"
]

scopes = JSON.parse(File.read("config/scopes.json"))
policies = JSON.parse(File.read("config/policies.json"))
token = nil

#----------------------------------------------------------
# customs helpers
#----------------------------------------------------------

helpers do

	# a helper method to turn a string ID
	# representation into a BSON::ObjectId
	def to_object_id val
		BSON::ObjectId.from_string(val)
	end

	def get_user_by_mail mail
		return settings.mongo_db["users"].find_one(:mail => mail).to_json
	end

	def get_token_by_hash hash
		return settings.mongo_db["tokens"].find_one(:hash => hash).to_json
	end

	def get_token_by_id id
		return settings.mongo_db["tokens"].find_one(:_id => BSON::ObjectId(id)).to_json
	end

	def verif_token secret, try_expirating=true

		#check if secret is provided
		if !secret
			datas = {
				"status" => 403,
				"message" => "secret must be provided"
			}
			return false, "#{datas.to_json}"
		end
	
		#retrieve token from api_key
		puts secret
		token = get_token_by_hash secret
		token_exists = token=="null" ? false : true

		#check if provided token exists
		if !token_exists

			datas = {
				"status" => 403,
				"message" => "Provided secret is incorrect"
			}
			return false, "#{datas.to_json}"
		end

		token = JSON.parse(token)

		#check if provided token is correct
		if token["hash"] != secret
			datas = {
				"status" => 403,
				"message" => "Wrong secret"
			}
			return false, "#{datas.to_json}"
		end

		#check token's lifetime
		if Time.parse(token["lifetime"]) < Time.now and try_expirating
			datas = {
				"status" => 403,
				"message" => "Expirated token"
			}
			return false, "#{datas.to_json}"
		end

		return true, token

	end

	def check_params params,required
		required.each do |param|
			if !params.keys.include? param
				datas = {
					"status" => 403,
					"message" => "Provided parameters are incorrects, param #{param} required"
				}
				return false, "#{datas.to_json}"
			end
		end

		return true, nil
	end 

	def check_headers required
		required.each do |param|
			if !env.keys.include? "HTTP_"+param.split.join("_").upcase
				datas = {
					"status" => 403,
					"message" => "Provided parameters are incorrects, header #{param} required"
				}
				return false, "#{datas.to_json}"
			end
		end

		return true, nil
	end 

	def get_label_type verb
		verbToLabel = {
			"GET" => "success",
			"POST" => "warning",
			"DELETE" => "danger",
			"PUT"=>"primary"
		}
		verbToLabel[verb]
	end

	def set_color_status status
		status_array = {
			"2"=>"success_status",
			"4"=>"error_status"
		}
		status.to_s[0]
		status_array[status.to_s[0]]
	end

	def scope_verification token, scopes
		#check scope exists?
		if !scopes.include? token["scope"]
			false
		end
		#check authorization
		scope = scopes[token["scope"]]
		if scope["type"] == "authorize"
			for route in scope["exceptions"] do
				if route == env["sinatra.route"]
					return true
				end
			end
			return false
		elsif scope["type"] == "forbidden"
			for route in scope["exceptions"] do
				if route == env["sinatra.route"]
					return false
				end
			end
			return true
		end
	end
end


#----------------------------------------------------------
# ****************BEFORE FILTER****************************
#----------------------------------------------------------

before do
	#retrieves route
	route = env["REQUEST_METHOD"]+" "+env["PATH_INFO"]
	#checks if this route exists
	routes_tmp = []
	routes = []
	Sinatra::Application.each_route do |route_|
		if route_.verb != "HEAD"
	 		routes_tmp.push [route_.verb, route_.path]
	 	end
	end
	routes_tmp.sort_by! {|m| m[1]}
	routes_tmp.each do |route_|
		routes.push route_.join(" ")
	end

	#refactoring route
	verb = route.split[0]
	splitted =  (route.split[1].split "/")[1..-1]
	if splitted.length > 1
		splitted[1] = ":id"
	end

	route = verb+" /"+splitted.join("/")

	if !routes.include? route
		halt slim :error_404, :locals => locals
	end 
	#check if route out of REST api
	if !route_exceptions.include? route
		#check if policies exists
		if policies.include? route
			if policies[route]["headers"] and policies[route]["headers"].length
				ok, result = check_headers policies[route]["headers"]
				if !ok
					status 403
					content_type :json
					halt result
				end
			end

			if policies[route]["params"] and policies[route]["params"].length
				params = env["rack.request.form_hash"]
				#check if all parameters are provided
				ok, res = check_params params, policies[route]["params"]

				if !ok
					status 403
					content_type :json
					halt res
				end	

			end

		end

		if env["REQUEST_METHOD"] == "GET"
			secret = env["HTTP_SECRET"]
		else
			secret = env["rack.request.form_hash"]["secret"]
		end

		ok, result = verif_token secret
		if !ok
			status 403
			content_type :json
			halt result
		end
		token = result

		ok = scope_verification token, scopes

		if !ok
			status 403
			content_type :json
			result = {
				"status" => 403,
				"message" => "Scope #{token["scope"]} not allowed"
			}
			halt "#{result.to_json}"
		end

	end
end

#----------------------------------------------------------
# ****************CONTROLLERS******************************
#----------------------------------------------------------


#----------------------------------------------------------
# root views
#----------------------------------------------------------

get "/" do
	status 200
	content_type :html
	datas = JSON.parse(File.read("config/api_doc.json"))
	puts datas["routes"].keys
	locals[:datas] = datas
	locals[:bloc_id] = 0
	locals[:label_type] = "info"
	slim :doc, :locals => locals
end

#----------------------------------------------------------
# routes views
#----------------------------------------------------------

get '/routes' do
	routes_tmp = []
	routes = []
	Sinatra::Application.each_route do |route|
		if route.verb != "HEAD"
	 		routes_tmp.push [route.verb, route.path]
	 	end
	end
	routes_tmp.sort_by! {|m| m[1]}
	routes_tmp.each do |route|
		routes.push route.join(" ")
	end
	locals[:routes] = routes
	slim :home, :locals => locals
end

#----------------------------------------------------------
# register views
#----------------------------------------------------------


get "/auth/register" do
	locals.delete :api_key
	locals[:mail_exists] = false
	slim :register, :locals => locals
end

post "/auth/register" do

	#Form verification
	form do 
		filters :strip
		field :mail, :present => true, :email => true
		field :password, :present => true,  :regexp => %r{^(?=.*\d)(?=.*[a-zA-Z])(?!.*[\W_\x7B-\xFF]).{6,15}$}
		same :verification, [:password, :verification]
	end

	mail_exists = (get_user_by_mail params[:mail]) == "null" ? false : true

	if form.failed? or mail_exists
		locals[:mail_exists] = mail_exists
		slim :register, :locals => locals
	else
		locals[:api_key] = hash = Digest::SHA1.hexdigest(params[:password]+Time.now.to_s+salt)
		locals[:refresh] = refresh_token = Digest::SHA1.hexdigest(hash)

		datas = {
					"hash" => hash,
					"scope" => "core_client",
					"lifetime" => Time.now + lifetime_tokens[:api_token],
					"status" => "active",
					"type" => "api_key",
					"refresh_token" => refresh_token
				}

		new_id = settings.mongo_db['tokens'].insert datas

		datas = {	
					"password" => Digest::SHA1.hexdigest(params[:password]), 
					"mail" => params[:mail],
					"api_token" => new_id
				}

		new_id = settings.mongo_db['users'].insert datas

		slim :register, :locals => locals
	end
end

#----------------------------------------------------------
# login views
#----------------------------------------------------------

get "/auth/login" do
	locals.delete :api_key
	locals[:mail_exists] = true
	locals[:wrong_password] = false
	slim :login, :locals => locals
end

post "/auth/login" do

	#Form verification
	form do 
		filters :strip
		field :mail, :present => true, :email => true
		field :password, :present => true,  :regexp => %r{^(?=.*\d)(?=.*[a-zA-Z])(?!.*[\W_\x7B-\xFF]).{6,15}$}
	end

	user = get_user_by_mail params[:mail]
	mail_exists = user == "null" ? false : true
	wrong_password = false

	if mail_exists
		user = JSON.parse(get_user_by_mail params[:mail])
		wrong_password = Digest::SHA1.hexdigest(params[:password]) != user["password"]
	end

	if form.failed? or !mail_exists or wrong_password

		if mail_exists
			locals[:wrong_password] = wrong_password
		end

		locals[:mail_exists] = mail_exists
		slim :login, :locals => locals
	else
		token = JSON.parse(get_token_by_id user["api_token"]["$oid"])

		locals[:api_key] = token["hash"]
		locals[:refresh] = token["refresh_token"]
		slim :login, :locals => locals
	end
end

#----------------------------------------------------------
# token api
#----------------------------------------------------------

post "/auth/token" do
	content_type :json
	status 403

	ok, result = verif_token params[:secret]
	if !ok
		return result
	end

	if token["type"] != "api_key"
		datas = {
			"status" => 403,
			"message" => "Wrong type of token"
		}
		"#{datas.to_json}"
	end


	#if user asks an unknown scope, generate an read_only token
	scope = (params[:scope] and available_scopes.include? params[:scope]) ? params[:scope] : "read_only"
	lifetime = Time.now + lifetime_tokens[:acces_token ]

	owner_api = to_object_id(token["_id"]["$oid"])

	#generate new token_access
	datas = {
		"hash" => Digest::SHA1.hexdigest(params[:secret]+Time.now.to_s+salt),
		"scope" => scope,
		"lifetime" => lifetime, #lifetime: 3h
		"status" => "active",
		"type" => "access",
		"refresh_token" => Digest::SHA1.hexdigest(hash.to_s),
		"owner_api" => owner_api
	}

	settings.mongo_db['tokens'].insert datas

	status 200

	datas = {
		"status" => 200,
		"lifetime" => lifetime,
		"token" => datas["hash"],
		"refresh_token" => datas["refresh_token"]
	}

	"#{datas.to_json}"
end

post "/auth/token/refresh" do
	status 403
	content_type :json

	ok, result = verif_token params[:secret],false
	if !ok
		return result
	end

	token = result	

	#check if refresh_token is provided
	if !params[:refresh_token]
		datas = {
			"status" => 403,
			"message" => "refresh_token must be provided"
		}
		return "#{datas.to_json}"
	end


	#check if provided refresh_token is correct
	if token["refresh_token"] != params[:refresh_token]
		datas = {
			"status" => 403,
			"message" => "Wrong refresh_token"
		}
		return "#{datas.to_json}"
	end

	status 200

	hash = Digest::SHA1.hexdigest(params[:secret]+Time.now.to_s+salt)
	refresh_token = Digest::SHA1.hexdigest(hash)

	if token["type"] == "api_key"
		lifetime = Time.now + lifetime_tokens[:api_token]
	elsif token["type"] == "access"
		lifetime = Time.now +  lifetime_tokens[:acces_token]
	end

	id = to_object_id(token["_id"]["$oid"])

	result =  settings.mongo_db['tokens'].update(
		{:_id => id},
		{
			"$set" =>{
				:hash => hash,
				:refresh_token => refresh_token,
				:lifetime => lifetime
			} 
		}
	)

	datas = {
		"status" => 200,
		"lifetime" => lifetime,
		"token" => hash,
		"refresh_token" => refresh_token
	}

	"#{datas.to_json}"
end

#----------------------------------------------------------
#*************************REST*****************************
#----------------------------------------------------------


#----------------------------------------------------------
# users routes
#----------------------------------------------------------

#retrieve users
get "/users" do
	

	status 404
	content_type :json
	datas = {
		"status" => 404,
		"message" => "Not Implemented yet"
	}
	"#{datas.to_json}"
end



#----------------------------------------------------------
# projects routes
#----------------------------------------------------------

#retrieve projects
get "/projects" do
	
	status 200

	results = JSON.parse(settings.mongo_db['projects'].find.to_a.to_json)

	datas = {}

	results.each do |project|
		datas.merge!(project["_id"]["$oid"] => {:sprints=>project["sprints"], :name => project["name"]})
	end

	#datas["error"] = 200

	datas.to_json

	"#{datas.to_json}"
end

#retrieve project id
get "/projects/:id" do

	status 404
	datas = {
		"status" => 404,
		"message" => "Not Implemented yet"
	}
	"#{datas.to_json}"
end

#create a project
post "/projects" do
	
	datas = {
		"name" => params[:name],
		"state" => "active",
		"sprints" => []
	}

	settings.mongo_db['projects'].insert datas

	datas = {
		"status" => 200,
		"message" => "Project inserted"
	}
	"#{datas.to_json}"
end

#update a project
post "/projects/:id" do

	status 404
	datas = {
		"status" => 404,
		"message" => "Not Implemented yet"
	}
	"#{datas.to_json}"
end

#----------------------------------------------------------
# test views
#----------------------------------------------------------

get "/test/docs" do
	content_type :json
	datas = JSON.parse(File.read("config/api_doc.json"))
	"#{JSON.pretty_generate(scopes)}"
end

get "/test/status/:verb" do
	"#{set_color_status params[:verb]}"
end

get '/test/env/:id' do
	"#{JSON.pretty_generate(env)}"
end