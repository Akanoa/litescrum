#!/usr/bin/ruby
# encoding: ASCII-8BIT 

require "sinatra"
require "sinatra/reloader"
require 'sinatra/formkeeper'
require "slim"
require "digest"
require "time"

require 'mongo'
require 'json'
require 'json/ext' # required for .to_json


#---------------------------------------------------------
# globals variables
#---------------------------------------------------------

include Mongo

configure do
  conn = MongoClient.new("localhost", 27017)
  set :mongo_connection, conn
  set :mongo_db, conn.db('litescrum')
end

locals = {:author => "Noa", :host => "http://localhost:4567"}

salt = "}!=zY1RsS-IV{bO?GYK,4h~lhcu[Djh%S$(/=>+0B_onaDA2@S!!@$tsE-s-TTKq"
available_scopes = ["read_only", "core_client"]

#define how many time a token is valid from his creation
lifetime_tokens = {
	:admin_token => (60*60*24*365*1000),#lifetime: 1000 years
	:api_token   => (60*60*24*365),#lifetime: 1 years
	:acces_token => (60*60*3)#lifetime: 3 hours
}

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

	def verif_token params,try_expirating=true

		#check if secret is provided
		if !params[:secret]
			datas = {
				"error" => 403,
				"message" => "secret must be provided"
			}
			return false, "#{datas.to_json}"
		end
	
		#retrieve token from api_key
		token = get_token_by_hash params[:secret]
		token_exists = token=="null" ? false : true

		#check if provided token exists
		if !token_exists

			datas = {
				"error" => 403,
				"message" => "Provided secret is incorrect"
			}
			return false, "#{datas.to_json}"
		end

		token = JSON.parse(token)

		#check if provided token is correct
		if token["hash"] != params[:secret]
			datas = {
				"error" => 403,
				"message" => "Wrong secret"
			}
			return false, "#{datas.to_json}"
		end

		#check token's lifetime
		if Time.parse(token["lifetime"]) < Time.now and try_expirating
			datas = {
				"error" => 403,
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
					"error" => 403,
					"message" => "Provided parameters are incorrects"
				}
				return false, "#{datas.to_json}"
			end
		end

		return true, nil
	end 

	def check_headers env,required
		required.each do |param|
			if !env.keys.include? "HTTP_"+param.split.join("_").upcase
				datas = {
					"error" => 403,
					"message" => "Provided parameters are incorrects, header #{param} required"
				}
				return false, "#{datas.to_json}"
			end
		end

		return true, nil
	end 
end

#----------------------------------------------------------
# ****************CONTROLLERS******************************
#----------------------------------------------------------


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

	ok, result = verif_token params
	if !ok
		return result
	end

	token = result

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
		"error" => 200,
		"lifetime" => lifetime,
		"token" => datas["hash"],
		"refresh_token" => datas["refresh_token"]
	}

	"#{datas.to_json}"
end

post "/auth/token/refresh" do
	status 403
	content_type :json

	ok, result = verif_token params,false
	if !ok
		return result
	end

	token = result	

	#check if refresh_token is provided
	if !params[:refresh_token]
		datas = {
			"error" => 403,
			"message" => "refresh_token must be provided"
		}
		return "#{datas.to_json}"
	end


	#check if provided refresh_token is correct
	if token["refresh_token"] != params[:refresh_token]
		datas = {
			"error" => 403,
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
		"error" => 200,
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
		"error" => 404,
		"message" => "Not Implemented yet"
	}
	"#{datas.to_json}"
end



#----------------------------------------------------------
# projects routes
#----------------------------------------------------------

#retrieve projects
get "/projects" do
	status 403
	content_type :json

	ok, result = check_headers env,["secret"]
	if !ok
		return result
	end

	params["secret"] = env["HTTP_SECRET"]
 
	ok, result = verif_token params
	if !ok
		return result
	end


	token = result	
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
	status 403
	content_type :json

	ok, result = verif_token params
	if !ok
		return result
	end

	token = result	
	status 404
	datas = {
		"error" => 404,
		"message" => "Not Implemented yet"
	}
	"#{datas.to_json}"
end

#create a project
post "/projects" do
	status 403
	content_type :json

	ok, result = verif_token params
	if !ok
		return result
	end

	token = result	
	status 200

	#check if all parameters are provided
	ok, res = check_params params,["name"]

	if !ok
		return res
	end	

	datas = {
		"name" => params[:name],
		"state" => "active",
		"sprints" => []
	}

	settings.mongo_db['projects'].insert datas

	datas = {
		"error" => 200,
		"message" => "Project inserted"
	}
	"#{datas.to_json}"
end

#update a project
put "/projects/:id" do
	status 403
	content_type :json

	ok, result = verif_token params
	if !ok
		return result
	end

	token = result	
	status 404
	datas = {
		"error" => 404,
		"message" => "Not Implemented yet"
	}
	"#{datas.to_json}"
end

#----------------------------------------------------------
# test views
#----------------------------------------------------------

get "/test/:mail" do
	params[:mail]
	value = (get_user_by_mail params[:mail]) == "null" ? false : true
	puts value
	if value 
	puts "pas fail"
	"#{value}"
	else
	puts "echec"
	"yolo"
	end
end


get "/" do
	"Hello world hay 32"
end
