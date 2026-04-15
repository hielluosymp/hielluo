import os
import json
import firebase_admin
from firebase_admin import credentials, auth
from flask import Flask, render_template, request, jsonify, Response, stream_with_context
import cohere

_sa = os.environ.get("FIREBASE_SERVICE_ACCOUNT")
cred = credentials.Certificate(json.loads(_sa) if _sa else "serviceAccountKey.json")
firebase_admin.initialize_app(cred)

app = Flask(__name__)
cohere_client = cohere.ClientV2(api_key=os.environ.get("COHERE_API_KEY"))

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/argentaurius")
def argentaurius():
    return render_template("chatbots/argentaurius.html")

@app.route("/argentaurius/chat", methods=["POST"])
def argentaurius_chat():
    data = request.json
    if not data or not data.get("message", "").strip():
        return jsonify({"error": "Message is required"}), 400
    user_message = data["message"].strip()
    history = data.get("history", [])
    messages = [{"role": "system", "content": "You are Argentaurius, a helpful and knowledgeable AI assistant."}]
    for msg in history:
        role = "user" if msg["role"] == "user" else "assistant"
        messages.append({"role": role, "content": msg["content"]})
    messages.append({"role": "user", "content": user_message})

    def generate():
        try:
            stream = cohere_client.chat_stream(model="command-r-08-2024", messages=messages)
            for event in stream:
                try:
                    if (event.type == "content-delta" and event.delta and event.delta.message
                            and event.delta.message.content and event.delta.message.content.text):
                        yield f"data: {json.dumps({'chunk': event.delta.message.content.text})}\n\n"
                except AttributeError:
                    pass
            yield f"data: {json.dumps({'done': True})}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'error': str(e)})}\n\n"

    return Response(stream_with_context(generate()), content_type='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})

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
