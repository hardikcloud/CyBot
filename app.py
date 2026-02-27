from flask import Flask, render_template, request, jsonify
from ollama_service import get_ai_response
from virustotal_service import scan_url_virustotal
from splunk_service import fetch_failed_logins
from database import (
    init_db,
    create_session,
    save_message,
    get_sessions,
    get_messages
)

app = Flask(__name__)
init_db()


@app.route("/")
def home():
    return render_template("index.html")

@app.route("/scan")
def scan_page():
    return render_template("scan.html")

@app.route("/scan_url", methods=["POST"])
def scan_url():
    data = request.get_json()
    url = data.get("url")

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    result = scan_url_virustotal(url)

    return jsonify(result)


@app.route("/chat", methods=["POST"])
def chat():
    data = request.get_json()

    user_message = data.get("message")
    session_id = data.get("session_id")

    if not user_message:
        return jsonify({"reply": "No message received."})

    # 🆕 Create new session with auto title
    if not session_id:
        title = " ".join(user_message.split()[:5]).capitalize()
        session_id = create_session(title)

    # Save user message
    save_message(session_id, "user", user_message)

    # AI reply
    reply = get_ai_response(user_message)

    # Save bot reply
    save_message(session_id, "bot", reply)

    return jsonify({
        "reply": reply,
        "session_id": session_id
    })


@app.route("/sessions")
def sessions():
    sessions = get_sessions()
    return jsonify([
        {"id": s[0], "title": s[1]}
        for s in sessions
    ])


@app.route("/messages/<int:session_id>")
def messages(session_id):
    messages = get_messages(session_id)
    return jsonify([
        {"role": m[0], "content": m[1]}
        for m in messages
    ])


@app.route("/delete_session/<int:session_id>")
def delete_session(session_id):

    import sqlite3

    conn = sqlite3.connect("cybot.db")
    cursor = conn.cursor()

    cursor.execute("DELETE FROM messages WHERE session_id=?", (session_id,))
    cursor.execute("DELETE FROM sessions WHERE id=?", (session_id,))

    conn.commit()
    conn.close()

    return jsonify({"status": "deleted"})
    
  
if __name__ == "__main__":
    app.run(debug=True)