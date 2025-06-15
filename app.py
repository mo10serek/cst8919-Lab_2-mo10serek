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
WORKSPACE_ID = "ccd6d987-010d-48ae-a441-a66930d65ac0"
SHARED_KEY = "OeBD8H/8+kdJCUOT3sepqausRYY5QCakFolyl9f/ZXuGrPSkjA7soFFrNu3vsxWVcrzeUOj0S+DD5NPDUx6JtQ=="
LOG_TYPE = "LoginAttempts"

# --- Helper function to build authorization header ---
def build_signature(date, content_length, method, content_type, resource):
    x_headers = f'x-ms-date:{date}'
    string_to_hash = f"{method}\n{content_length}\n{content_type}\n{x_headers}\n{resource}"
    bytes_to_hash = bytes(string_to_hash, encoding="utf-8")
    decoded_key = base64.b64decode(SHARED_KEY)
    encoded_hash = hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()
    return f"SharedKey {WORKSPACE_ID}:{base64.b64encode(encoded_hash).decode()}"

# --- Send log entry to Azure Log Analytics ---
def send_log(data):
    body = json.dumps([data])
    content_length = len(body)
    rfc1123date = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    signature = build_signature(rfc1123date, content_length, 'POST', 'application/json', f'/api/logs')

    uri = f'https://{WORKSPACE_ID}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01'
    headers = {
        'Content-Type': 'application/json',
        'Authorization': signature,
        'Log-Type': LOG_TYPE,
        'x-ms-date': rfc1123date
    }

    response = requests.post(uri, data=body, headers=headers)
    return response.status_code

# --- Flask /login route ---
@app.route('/login', methods=['POST'])
def login():
    ip = request.remote_addr
    username = request.form.get('username')
    password = request.form.get('password')

    # Dummy check — replace with real auth

    return jsonify({"username": username, "password": password})
    if username == "mo10serek" or password == "mX10baz3m":
        # On successful login
        log_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "ip": ip,
            "username": username,
            "status": "success",
            "attempts": failed_logins.get(ip, 0)
        }
        send_log(log_data)
        failed_logins[ip] = 0  # reset on success

        return jsonify({"success": True, "message": "Logged in successfully."})

    failed_logins[ip] = failed_logins.get(ip, 0) + 1

    log_data = {
        "timestamp": datetime.utcnow().isoformat(),
        "ip": ip,
        "username": username,
        "status": "failed",
        "attempts": failed_logins[ip]
    }
    send_log(log_data)

    return jsonify({"success": False, "message": "Invalid credentials."})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)