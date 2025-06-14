from flask import Flask, request, jsonify
import requests
import json
import datetime
import hashlib
import hmac
import base64
import os

app = Flask(__name__)

# Replace with your actual Log Analytics workspace ID and key
LOG_ANALYTICS_WORKSPACE_ID = os.environ.get("LOG_ANALYTICS_WORKSPACE_ID")
LOG_ANALYTICS_SHARED_KEY = os.environ.get("LOG_ANALYTICS_SHARED_KEY")
LOG_ANALYTICS_LOG_TYPE = "LoginLogs"

def build_signature(date, content_length, method, content_type, resource):
    x_headers = f'x-ms-date:{date}'
    string_to_hash = f"{method}\n{str(content_length)}\n{content_type}\n{x_headers}\n{resource}"
    bytes_to_hash = bytes(string_to_hash, encoding="utf-8")
    decoded_key = base64.b64decode(LOG_ANALYTICS_SHARED_KEY)
    encoded_hash = base64.b64encode(
        hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()
    ).decode()
    return f"SharedKey {LOG_ANALYTICS_WORKSPACE_ID}:{encoded_hash}"

def send_to_log_analytics(log_data):
    json_data = json.dumps(log_data)
    rfc1123date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    content_length = len(json_data)
    method = 'POST'
    content_type = 'application/json'
    resource = f'/api/logs'

    signature = build_signature(rfc1123date, content_length, method, content_type, resource)

    uri = f"https://{LOG_ANALYTICS_WORKSPACE_ID}.ods.opinsights.azure.com{resource}?api-version=2016-04-01"

    headers = {
        'Content-Type': content_type,
        'Authorization': signature,
        'Log-Type': LOG_ANALYTICS_LOG_TYPE,
        'x-ms-date': rfc1123date
    }

    response = requests.post(uri, data=json_data, headers=headers)
    response.raise_for_status()  # raise error if not successful
    return response.status_code

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    ip_address = request.remote_addr

    # Log the attempt
    log_entry = {
        "Username": username,
        "IPAddress": ip_address,
        "Timestamp": datetime.datetime.utcnow().isoformat() + "Z"
    }

    try:
        send_to_log_analytics(log_entry)
        return jsonify({"message": "Login logged"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)