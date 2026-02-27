from flask import Flask, render_template, request, jsonify
from dotenv import load_dotenv
import os
import re
from werkzeug.utils import secure_filename

# Load environment variables
load_dotenv()

# Services
from ollama_service import get_ai_response
from virustotal_service import scan_url_virustotal, scan_file_virustotal
from splunk_service import fetch_failed_logins

# Database
from database import (
    init_db,
    create_session,
    save_message,
    get_sessions,
    get_messages
)

app = Flask(__name__)
init_db()


# =========================
# 🔥 Intent + Time Parser
# =========================
def parse_intent_and_time(message):
    text = message.lower()

    if "yesterday" in text:
        time_range = "yesterday"
    elif "last 7" in text or "7 days" in text:
        time_range = "last_7d"
    elif "last 30" in text or "month" in text:
        time_range = "last_30d"
    else:
        time_range = "last_24h"

    if "failed" in text and "ssh" in text:
        intent = "SSH_FAILED"
    elif "successful" in text:
        intent = "SSH_SUCCESS"
    elif "sudo" in text:
        intent = "SUDO"
    elif "attack" in text or "security summary" in text:
        intent = "SECURITY_SUMMARY"
    else:
        intent = "CHAT"

    return intent, time_range


# =========================
# HOME & PAGES
# =========================
@app.route("/")
def home():
    return render_template("index.html")


@app.route("/scan")
def scan_page():
    return render_template("scan.html")


# =========================
# VIRUSTOTAL - URL SCAN
# =========================
@app.route("/scan_url", methods=["POST"])
def scan_url():
    data = request.get_json()
    url = data.get("url")

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    result = scan_url_virustotal(url)
    return jsonify(result)


# =========================
# VIRUSTOTAL - FILE SCAN
# =========================
@app.route("/scan_file", methods=["POST"])
def scan_file():

    if "file" not in request.files:
        return jsonify({"error": "No file provided"})

    file = request.files["file"]

    if file.filename == "":
        return jsonify({"error": "Empty file name"})

    filename = secure_filename(file.filename)

    upload_folder = "uploads"
    os.makedirs(upload_folder, exist_ok=True)

    filepath = os.path.join(upload_folder, filename)
    file.save(filepath)

    result = scan_file_virustotal(filepath)

    if os.path.exists(filepath):
        os.remove(filepath)

    return jsonify(result)


# =========================
# CHAT SYSTEM
# =========================
@app.route("/chat", methods=["POST"])
def chat():
    data = request.get_json()

    user_message = data.get("message")
    session_id = data.get("session_id")

    if not user_message:
        return jsonify({"reply": "No message received."})

    if not session_id:
        title = " ".join(user_message.split()[:5]).capitalize()
        session_id = create_session(title)

    save_message(session_id, "user", user_message)

    user_lower = user_message.lower()

    # =========================
    # SSH LOGIC (IMPROVED)
    # =========================
    if "log" in user_lower or "failed" in user_lower or "ssh" in user_lower:

        logs = fetch_failed_logins()

        if not logs or isinstance(logs, dict):
            reply = "No failed SSH login attempts found or Splunk error occurred."
        else:
            usernames = set()
            ips = set()

            for line in logs:
                # Extract username (invalid user OR normal user)
                user_match_invalid = re.search(r"invalid user (\w+)", line)
                user_match_normal = re.search(r"Failed password for (\w+)", line)
                ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)

                if user_match_invalid:
                    usernames.add(user_match_invalid.group(1))

                if user_match_normal:
                    usernames.add(user_match_normal.group(1))

                if ip_match:
                    ips.add(ip_match.group(1))

            username_list = ", ".join(usernames) if usernames else "None"
            ip_list = ", ".join(ips) if ips else "None"

            brute_force = "Yes" if len(logs) > 5 else "No"

            # Structured data to AI (NO RAW LOGS)
            ai_prompt = f"""
You are a cybersecurity assistant.

Respond ONLY in clean bullet points.
No paragraphs.

🔐 Security Summary

• Total Failed Attempts: {len(logs)}
• Suspicious IPs: {ip_list}
• Targeted Usernames: {username_list}
• Brute-force Detected: {brute_force}
• Recommendation: Secure SSH and monitor suspicious IPs.
"""

            reply = get_ai_response(ai_prompt)

    else:
        reply = get_ai_response(user_message)

    save_message(session_id, "bot", reply)

    return jsonify({
        "reply": reply,
        "session_id": session_id
    })


# =========================
# SESSION MANAGEMENT
# =========================
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


# =========================
# RUN
# =========================
if __name__ == "__main__":
    app.run(debug=True)