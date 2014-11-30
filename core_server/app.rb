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

#----------------------------------------------------------
# customs helpers
#----------------------------------------------------------

helpers do

	# a helper method to turn a string ID
	# representation into a BSON::ObjectId
	def object_id val
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
		locals[:refresh] = hash = Digest::SHA1.hexdigest(hash)

		datas = {
					"hash" => hash,
					"scope" => "core_client",
					"life_time" => Time.now + (60*60*24*30*3),
					"status" => "active",
					"type" => "api_key",
					"refresh_token" => Digest::SHA1.hexdigest(hash)
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
	api_key = params[:secret]
	content_type :json

	status 403


	#check if secret is provided
	if !api_key
		datas = {
			"error" => 403,
			"message" => "You must provide a secret with you request, check documention for more information"
		}
		return "#{datas}"
	end

	#retrieve token from api_key
	token = get_token_by_hash api_key
	token_exists = token=="null" ? false : true

	#check if provided token exists
	if !token_exists

		datas = {
			"error" => 403,
			"message" => "Provided secret is incorrect"
		}
		return "#{datas}"
	end

	token = JSON.parse(token)

	#check if provided token is correct
	if token["hash"] != params[:secret]
		datas = {
			"error" => 403,
			"message" => "Wrong secret"
		}
		return "#{datas}"
	end

	#if user asks an unknown scope, generate an read_only token
	scope = (params[:scope] and available_scopes.include? params[:scope]) ? params[:scope] : "read_only"

	#generate new token_access
	datas = {
		"hash" => Digest::SHA1.hexdigest(params[:secret]+Time.now.to_s+salt),
		"scope" => scope,
		"life_time" => Time.now + (60*60*3), #lifetime: 3h
		"status" => "active",
		"type" => "access",
		"refresh_token" => Digest::SHA1.hexdigest(hash.to_s)
	}

	settings.mongo_db['tokens'].insert datas

	status 200

	datas = {
		"error" => 200,
		"life_time" => 60*60*3,
		"token" => datas["hash"],
		"refresh_token" => datas["refresh_token"]
	}

	"#{datas}"
end

post "/auth/token/refresh" do
	status 403

	#check if secret is provided
	if !params[:secret]
		datas = {
			"error" => 403,
			"message" => "secret must be provided"
		}
		return "#{datas}"
	end

	#check if refresh_token is provided
	if !params[:refresh_token]
		datas = {
			"error" => 403,
			"message" => "refresh_token must be provided"
		}
		return "#{datas}"
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
		return "#{datas}"
	end

	token = JSON.parse(token)

	#check if provided token is correct
	if token["hash"] != params[:secret]
		datas = {
			"error" => 403,
			"message" => "Wrong secret"
		}
		return "#{datas}"
	end

	#check if provided refresh_token is correct
	if token["refresh_token"] != params[:refresh_token]
		datas = {
			"error" => 403,
			"message" => "Wrong refresh_token"
		}
		return "#{datas}"
	end

	status 200

	token = JSON.parse(get_token_by_hash params[:secret])

	hash = Digest::SHA1.hexdigest(params[:secret]+Time.now.to_s+salt)
	refresh_token = Digest::SHA1.hexdigest(hash)

	if token["type"] == "api_key"
		lifetime = Time.now + (60*60*3) #lifetime: 3h
	elsif token["type"] == "access"
		lifetime = Time.now + (60*60*24*30*3) #lifetime: 3 months
	end

	id = object_id(token["_id"]["$oid"])

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
		"life_time" => lifetime,
		"token" => hash,
		"refresh_token" => refresh_token
	}

	"#{datas}"
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