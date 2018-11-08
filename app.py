from flask import Flask, g, render_template, jsonify, url_for, flash
from flask import request, redirect, make_response
from flask import session as login_session
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from functools import wraps
from database_setup import User
from oauth2client.client import flow_from_clientsecrets, FlowExchangeError
import random
import string
import json
import datetime
import hashlib
import httplib2
import requests

app = Flask(__name__)

CLIENT_ID = json.loads(
		open('client_secrets.json', 'r').read())['web']['client_id']

## Connect to Database and create database session
engine = create_engine('sqlite:///tp.db')
User.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

@app.route('/login', methods=['GET', 'POST'])
def login():

	if request.method == 'GET':
		state = ''.join(random.choice(
				string.ascii_uppercase + string.digits) for x in range(32))
		# store it in session for later use
		login_session['state'] = state
		return render_template('login.html', STATE = state)
	else:
		if request.method == 'POST':
			print ("dentro de POST login")
			user = session.query(User).filter_by(
				username = request.form['username']).first()

			if user and valid_pw(request.form['username'],
								request.form['password'],
								user.pw_hash):
			
				login_session['username'] = request.form['username']
				return render_template('public.html', username=login_session['username'])

			else:
				error = "Usuario no registrado"
				return render_template('login.html', error = error)
				
# GConnect
@app.route('/gconnect', methods=['POST'])
def gconnect():
	print ("Dentro de GConnect")
		# Validate state token
	if request.args.get('state') != login_session['state']:
		response = make_response(json.dumps('Invalid state parameter.'), 401)
		response.headers['Content-Type'] = 'application/json'
		return response
	# Obtain authorization code, now compatible with Python3
	code = request.data

	try:
			# Upgrade the authorization code into a credentials object
		oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
		oauth_flow.redirect_uri = 'postmessage'
		credentials = oauth_flow.step2_exchange(code)
	except FlowExchangeError:
		response = make_response(
					json.dumps('Failed to upgrade the authorization code.'), 401)
		response.headers['Content-Type'] = 'application/json'
		return response

	# Check that the access token is valid.
	access_token = credentials.access_token
	url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
				 % access_token)
	# Submit request, parse response - Python3 compatible
	h = httplib2.Http()
	result = json.loads(h.request(url, 'GET')[1])

	# If there was an error in the access token info, abort.
	if result.get('error') is not None:
			response = make_response(json.dumps(result.get('error')), 500)
			response.headers['Content-Type'] = 'application/json'
			return response

	# Verify that the access token is used for the intended user.
	gplus_id = credentials.id_token['sub']
	if result['user_id'] != gplus_id:
			response = make_response(
					json.dumps("Token's user ID doesn't match given user ID."), 401)
			response.headers['Content-Type'] = 'application/json'
			return response

	# Verify that the access token is valid for this app.
	if result['issued_to'] != CLIENT_ID:
			response = make_response(
					json.dumps("Token's client ID does not match app's."), 401)
			print ("Token's client ID does not match app's.")
			response.headers['Content-Type'] = 'application/json'
			return response

	stored_credentials = login_session.get('credentials')
	stored_gplus_id = login_session.get('gplus_id')
	if stored_credentials is not None and gplus_id == stored_gplus_id:
			response = make_response(json.dumps('Current user is already connected.'),
																	 200)
			response.headers['Content-Type'] = 'application/json'
			return response

	# Store the access token in the session for later use.
	login_session['access_token'] = credentials.access_token
	login_session['gplus_id'] = gplus_id

	# Get user info
	userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
	params = {'access_token': access_token, 'alt': 'json'}
	answer = requests.get(userinfo_url, params=params)

	data = answer.json()

	login_session['username'] = data['name']
	login_session['picture'] = data['picture']
	login_session['email'] = data['email']

	output = ''
	output += '<h3>Welcome, '
	output += login_session['username']
	output += '!</h3>'
	output += '<img src="'
	output += login_session['picture']
	output += ' " style = "width: 100px; height: 100px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
	flash("you are now logged in as %s" % login_session['username'])
	print ("done!")
	print ("Usuario " + login_session['username'])
	return output
	

@app.route('/gdisconnect')
def gdisconnect():
				# Only disconnect a connected user.
		access_token = login_session.get('access_token')
		if access_token is None:
				response = make_response(
						json.dumps('Current user not connected.'), 401)
				response.headers['Content-Type'] = 'application/json'
				return response
		url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
		h = httplib2.Http()
		result = h.request(url, 'GET')[0]
		if result['status'] == '200':
				# Reset the user's sesson.
				del login_session['access_token']
				del login_session['gplus_id']
				del login_session['username']
				del login_session['email']
				del login_session['picture']
				response = make_response(json.dumps('Successfully disconnected.'), 200)
				response.headers['Content-Type'] = 'application/json'
				return redirect(url_for('showGenres'))
		else:
				# For whatever reason, the given token was invalid.
				response = make_response(
						json.dumps('Failed to revoke token for given user.', 400))
				response.headers['Content-Type'] = 'application/json'
		return response


def login_required(f):
	@wraps(f)
	def decorated_function(*args, **kwargs):
		if 'username' not in login_session:
			return redirect(url_for('login'))
		return f(*args, **kwargs)
	return decorated_function

@app.route('/logout')
def logout():
		
		del login_session['username']

		return render_template('public.html')

#main
@app.route('/', methods=['GET'])
@app.route('/public/', methods=['GET'])
def showMain():
	if 'email' in login_session:
		username = login_session['username']
		return render_template('public.html', username=username)
	else:	
		return render_template('public.html')


def main():
    app.run()
 

if __name__ == '__main__':
	app.secret_key = "secret key"
	app.debug = False
	app.run(host = '0.0.0.0', port = 8080)
