import json
import requests
import jwt
from flask import Flask, request, jsonify

app = Flask(__name__)

# Replace with your Entra ID Tenant ID
TENANT_ID = 'baa91130-3535-4c79-b3f4-2202979a83b8'
# Replace with your Application (Client) ID
CLIENT_ID = 'b6eced93-cdd2-44c1-9971-767d360b6611'
# URL to fetch the JWKS (public keys) for token validation
JWKS_URL = f"https://login.microsoftonline.com/{TENANT_ID}/discovery/v2.0/keys"

# Function to fetch the public keys from Microsoft Entra ID
def get_public_keys():
    response = requests.get(JWKS_URL)
    return response.json()["keys"]

# Function to verify the JWT token
def verify_jwt_token(token):
    # Fetch the public keys
    public_keys = get_public_keys()
    
    # Decode the token to get the "kid" (key ID) from the header
    unverified_header = jwt.get_unverified_header(token)
    if unverified_header is None or "kid" not in unverified_header:
        raise ValueError("Unable to find the 'kid' in the token header")

    # Find the correct public key
    rsa_key = {}
    for key in public_keys:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
            break

    if not rsa_key:
        raise ValueError("Unable to find appropriate key")

    # Verify the JWT token using the found public key
    try:
        payload = jwt.decode(
            token,
            rsa_key,
            algorithms=["RS256"],
            audience=CLIENT_ID
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise ValueError("Token has expired")
    except jwt.JWTClaimsError:
        raise ValueError("Invalid claims, please check the audience and issuer")
    except Exception as e:
        raise ValueError("Unable to parse token: " + str(e))

# Flask route to handle incoming API requests
@app.route("/query", methods=["POST"])
def query():
    # Get the JWT token from the Authorization header
    auth_header = request.headers.get("Authorization")
    if auth_header is None:
        return jsonify({"message": "Authorization header is missing"}), 400

    token = auth_header.split(" ")[1]  # Bearer <token>

    try:
        # Validate the token
        payload = verify_jwt_token(token)
        
        # Now that the token is valid, you can process the request
        username = request.json.get("username")
        if not username:
            return jsonify({"message": "Username is required"}), 400
        
        # Example response: You can interact with your database or other logic here
        return jsonify({"message": f"Query executed successfully for user {username}."})

    except ValueError as e:
        return jsonify({"message": str(e)}), 401


