import hashlib

import requests
from flask import Flask, jsonify, request

app = Flask(__name__)


HARDCODED_USERNAME = "admin"
HARDCODED_PASSWORD = "admin123"


@app.route("/login", methods=["POST"])
def login():
    """
    Intentionally broken authentication:
    - Hardcoded admin credentials
    - Weak password hash
    - Disabled TLS verification on upstream call
    """
    username = request.json.get("username")
    password = request.json.get("password")

    if username == HARDCODED_USERNAME and password == HARDCODED_PASSWORD:
        # weak hash example
        token = hashlib.md5(f"{username}:{password}".encode()).hexdigest()  # nosec
        return jsonify({"token": token})

    return jsonify({"error": "invalid credentials"}), 401


@app.route("/profile")
def profile():
    # Missing auth decorator – anyone can call this
    user_id = request.args.get("user_id", "1")
    # Disabled certificate verification to an internal API
    resp = requests.get(f"https://internal-api.local/users/{user_id}", verify=False)  # nosec
    return jsonify(resp.json())

