import flask
from flask import Flask, request, jsonify
import json
import pyotp
import secrets  
import base64

app = Flask(__name__)

# Function to load users from the JSON file
def load_users():
    with open(users_file, "r") as file:
        users_data = json.load(file)
    return users_data

# Load users from the JSON file
users_file = "users.json"
users_data = load_users()

# Generate a dynamic secret key using a secure random method
def generate_dynamic_secret_key():
    # Generate a random byte string
    random_bytes = secrets.token_bytes(10)
    # Encode the byte string in base32
    secret_key = base64.b32encode(random_bytes).decode('utf-8')
    return secret_key

# Method to get the 2fa key
@app.route('/get_2fa_key', methods=['POST'])
def get_2fa_key():
    data = request.get_json()
    username = data.get('username', None)

    app.logger.info(f'Received request for 2FA key from user: {username}')

    # Reload users_data from the file
    users_data = load_users()

    # Check if the user already has a secret key
    if username in users_data:
        app.logger.info(f'User {username} found. Checking for an existing secret key.')

        # If not, generate and assign a new dynamic secret key
        if 'secret_key' not in users_data[username]: 
            app.logger.info(f'Generating a new secret key for user: {username}')
            users_data[username]['secret_key'] = generate_dynamic_secret_key()

        # Use the dynamic secret key for TOTP generation
        secret_key = users_data[username]["secret_key"]
        totp = pyotp.TOTP(secret_key)
        current_code = totp.now()

        # Save the updated user dictionary to the JSON file
        with open(users_file, "w") as file:
            json.dump(users_data, file)

        app.logger.info(f'Successfully generated 2FA key for user: {username}')
        return jsonify({'secret_key': secret_key, 'current_code': current_code})

    app.logger.error(f'User not found: {username}')
    return jsonify({'error': 'User not found'})

# Route to generate a new dynamic secret key
@app.route('/generate_secret_key', methods=['POST'])
def generate_secret_key():
    data = request.get_json()
    username = data.get('username', None)

    app.logger.info(f'Received request to generate a secret key for user: {username}')

    if username is None:
        app.logger.error('Username not provided in the request.')
        return jsonify({'error': 'Username not provided'})

    secret_key = generate_dynamic_secret_key()

    # Reload users_data from the file
    users_data = load_users()

    # Check if the user already exists in the dictionary
    if username in users_data:
        app.logger.info(f'User {username} found. Generating a new secret key.')
        # Save the updated user dictionary to the JSON file
        with open(users_file, "w") as file:
            users_data[username]['secret_key'] = secret_key
            json.dump(users_data, file)

        app.logger.info(f'Successfully generated a secret key for user: {username}')
        return jsonify({'secret_key': secret_key})
    else:
        app.logger.error(f'User not found: {username}')
        return jsonify({'error': 'User not found'})

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)