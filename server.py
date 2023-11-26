import flask
from flask import Flask, request, jsonify
import json
import pyotp
import secrets  

app = Flask(__name__)

# Load users from the JSON file
users_file = "users.json"
with open(users_file, "r") as file:
    users_data = json.load(file)

# Generate a dynamic secret key using a secure random method
def generate_dynamic_secret_key():
    return secrets.token_hex(16)

# Method to get the 2fa key
@app.route('/get_2fa_key', methods=['POST'])
def get_2fa_key():
    data = request.get_json()
    username = data.get('username', None)

    # Check if the user already has a secret key
    if username in users_data:
        # If not, generate and assign a new dynamic secret key
        if 'secret_key' not in users_data[username]: 
            users_data[username]['secret_key'] = generate_dynamic_secret_key()

        # Use the dynamic secret key for TOTP generation
        secret_key = users_data[username]["secret_key"]
        totp = pyotp.TOTP(secret_key)
        current_code = totp.now()
        return jsonify({'secret_key': secret_key, 'current_code': current_code})

    return jsonify({'error': 'User not found'})

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)

# Update the users.json file with the changes
with open(users_file, "w") as file:
    json.dump(users_data, file)