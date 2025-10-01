import os
import requests
from flask import Flask, redirect, request, session, url_for, jsonify
from requests_oauthlib import OAuth2Session

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Azure AD configuration (replace these with your actual details)
TENANT_ID = 'baa91130-3535-4c79-b3f4-2202979a83b8'
CLIENT_ID = 'b8f3843f-9aeb-49c6-8838-7a2f8bf2cbed'
CLIENT_SECRET = 'DNB8Q~XfZ9dzkzHB11PwcisnFfdZlyNH9qxsEbBL'
REDIRECT_URI = 'https://ritesh-prac-eygvckezfhbhddea.canadacentral-01.azurewebsites.net/auth/callback'

# Azure AD OAuth 2.0 endpoints
AUTHORIZATION_URL = f'https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/authorize'
TOKEN_URL = f'https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token'
SCOPE = ["User.Read"]  # Scope to access basic profile information

# Route for the login page (Initiates authentication)
@app.route("/")
def index():
    # Check if user is logged in by checking the session token
    if 'oauth_token' not in session:
        return redirect(url_for('login'))
    # If authenticated, display "Hello World"
    return "Hello World"

# Route to handle the OAuth login redirect
@app.route("/login")
def login():
    # Create OAuth2Session to handle the OAuth flow
    azure = OAuth2Session(CLIENT_ID, redirect_uri=REDIRECT_URI, scope=SCOPE)
    authorization_url, state = azure.authorization_url(AUTHORIZATION_URL)
    # Store the state in the session to verify after callback
    session['oauth_state'] = state
    return redirect(authorization_url)

# Callback route to handle the redirect from Azure after successful login
@app.route("/auth/callback")
def callback():
    azure = OAuth2Session(CLIENT_ID, redirect_uri=REDIRECT_URI, state=session['oauth_state'])
    token = azure.fetch_token(TOKEN_URL, client_secret=CLIENT_SECRET, authorization_response=request.url)
    
    # Store the token in the session for use in subsequent requests
    session['oauth_token'] = token

    # Fetch user info from Microsoft Graph API to ensure authentication
    user_info = get_user_info(azure)

    # Now user is authenticated, redirect them back to the main page
    return redirect(url_for('index'))

# Function to fetch user info from Microsoft Graph API
def get_user_info(azure):
    user_info_url = "https://graph.microsoft.com/v1.0/me"
    response = azure.get(user_info_url)
    return response.json()

if __name__ == "__main__":
    # Gunicorn will handle the app execution, so we don't need app.run()
    pass
