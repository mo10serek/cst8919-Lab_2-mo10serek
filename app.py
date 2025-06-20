from flask import Flask, request, jsonify
from datetime import datetime
import requests
import hashlib
import hmac
import base64
import json
import time

app = Flask(__name__)

# In-memory store for failed login attempts (per IP)
failed_logins = {}

# Replace with your Azure Log Analytics workspace info
WORKSPACE_ID = "6427a9ec-cd12-4966-81e9-0dac7b4bbdac"
SHARED_KEY = "Cyr0Dspj7xPlyXTwFhH0R924nDSX73DaItL2wTPxBibzsPHq4Ex3FCTDuyd06CrVQ9NP0hrxdzD+lp1KQq/FNg=="
LOG_TYPE = "LoginAttempts"

# --- Helper function to build authorization header ---
def build_signature(content_length, method, content_type, resource):
    string_to_hash = f'{method}\n{content_length}\n{content_type}\n{resource}'
    bytes_to_hash = bytes(string_to_hash, encoding='utf-8')
    decoded_key = base64.b64decode(SHARED_KEY)
    encoded_hash = base64.b64encode(
        hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()
    ).decode()
    return f'SharedKey {WORKSPACE_ID}:{encoded_hash}'

# --- Send log entry to Azure Log Analytics ---
def send_log(log_data):
    body = json.dumps(log_data)
    signature = build_signature(len(body), 'POST', 'application/json', '/api/logs')

    uri = f'https://{WORKSPACE_ID}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01'

    headers = {
        'Content-Type': 'application/json',
        'Authorization': signature,
        'Log-Type': LOG_TYPE
    }

    response = requests.post(uri, data=body, headers=headers)
    print("Log sent:", response.status_code, response.text)

# --- Flask /login route ---
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    success = False

    if username == "mo10serek" and password == "mX10baz3":
        success = True
        result = {"message": "Login successful"}
        status = 200
    else:
        result = {"message": "Invalid credentials"}
        status = 401

    # Create and send log
    log_entry = {
        "username": username,
        "success": success,
        "ip": request.remote_addr,
        "user_agent": request.headers.get('User-Agent')
    }

    send_log(log_entry)

    return jsonify(result), status

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)