from flask import Flask, redirect, url_for, session,render_template
from flask_oauth import OAuth
 
 
# You must configure these 3 values from Google APIs console
# https://code.google.com/apis/console
GOOGLE_CLIENT_ID = '900289532673-ve04chl88hn3hs57dqghess3ttd3ukqh.apps.googleusercontent.com'
GOOGLE_CLIENT_SECRET = 'eZR8TsZUBF5j-N3xgfYWPaz2'
REDIRECT_URI = '/oauth2callback' 
 
SECRET_KEY = 'irtti'
DEBUG = True
 
app = Flask(__name__)
app.debug = DEBUG
app.secret_key = SECRET_KEY
oauth = OAuth()
 
google = oauth.remote_app('google',
                          base_url='https://www.google.com/accounts/',
                          authorize_url='https://accounts.google.com/o/oauth2/auth',
                          request_token_url=None,
                          request_token_params={'scope': 'https://www.googleapis.com/auth/userinfo.email',
                                                'response_type': 'code'},
                          access_token_url='https://accounts.google.com/o/oauth2/token',
                          access_token_method='POST',
                          access_token_params={'grant_type': 'authorization_code'},
                          consumer_key=GOOGLE_CLIENT_ID,
                          consumer_secret=GOOGLE_CLIENT_SECRET)
 
@app.route('/')
def Index():
    access_token = session.get('access_token')
    if access_token is None:
        return redirect(url_for('Login'))
 
    access_token = access_token[0]
    from urllib2 import Request, urlopen, URLError
 
    headers = {'Authorization': 'OAuth '+access_token}
    req = Request('https://www.googleapis.com/oauth2/v1/userinfo',
                  None, headers)
    try:
        res = urlopen(req)
    except URLError, e:
        if e.code == 401:
            # Unauthorized
            session.pop('access_token', None)
            return redirect(url_for('Login'))
        return res.read()
 
    return res.read()
 
 
@app.route('/Login')
def Login():
    callback=url_for('authorized', _external=True)
    return google.authorize(callback=callback)
 
 
 
@app.route(REDIRECT_URI)
@google.authorized_handler
def authorized(resp):
    access_token = resp['access_token']
    session['access_token'] = access_token, ''
    return redirect(url_for('Index'))
 
 
@google.tokengetter
def get_access_token():
    return session.get('access_token')
 
 
def main():
    app.run()
 
 
if __name__ == '__main__':
    main()