import os
import json
import firebase_admin
from firebase_admin import credentials, auth
from flask import Flask, render_template, request, jsonify

_sa = os.environ.get("FIREBASE_SERVICE_ACCOUNT")
cred = credentials.Certificate(json.loads(_sa) if _sa else "serviceAccountKey.json")
firebase_admin.initialize_app(cred)

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/auth/custom-token", methods=["POST"])
def custom_token():
    id_token = request.json.get("idToken")
    if not id_token:
        return jsonify({"error": "Missing idToken"}), 400
    try:
        decoded = auth.verify_id_token(id_token)
        custom = auth.create_custom_token(decoded["uid"])
        return jsonify({"customToken": custom.decode("utf-8")})
    except Exception as e:
        return jsonify({"error": str(e)}), 401

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
