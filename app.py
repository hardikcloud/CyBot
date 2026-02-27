from flask import Flask, render_template, request, jsonify
from ollama_service import get_ai_response
from virustotal_service import scan_url_virustotal
from splunk_service import fetch_auth_logs
from database import (
    init_db,
    create_session,
    save_message,
    get_sessions,
    get_messages
)

import re

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

    # Create new session
    if not session_id:
        title = " ".join(user_message.split()[:5]).capitalize()
        session_id = create_session(title)

    save_message(session_id, "user", user_message)

    user_lower = user_message.lower()

    # ===============================
    # AUTH.LOG SECURITY MONITORING
    # ===============================
    if "attack" in user_lower or "ssh" in user_lower or "log" in user_lower:

        logs = fetch_auth_logs()

        if not logs or isinstance(logs, dict):
            reply = "No authentication activity found or Splunk error occurred."
        else:
            failed_count = 0
            success_count = 0
            sudo_count = 0
            usernames = set()
            ips = set()

            for line in logs:

                # Failed SSH
                if "Failed password" in line:
                    failed_count += 1

                    user_invalid = re.search(r"invalid user (\w+)", line)
                    user_normal = re.search(r"Failed password for (\w+)", line)

                    if user_invalid:
                        usernames.add(user_invalid.group(1))
                    if user_normal:
                        usernames.add(user_normal.group(1))

                # Successful SSH
                if "Accepted password" in line:
                    success_count += 1
                    user_success = re.search(r"Accepted password for (\w+)", line)
                    if user_success:
                        usernames.add(user_success.group(1))

                # Sudo usage
                if "sudo:" in line:
                    sudo_count += 1
                    sudo_user = re.search(r"sudo:\s+(\w+)", line)
                    if sudo_user:
                        usernames.add(sudo_user.group(1))

                # Extract IP
                ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
                if ip_match:
                    ips.add(ip_match.group(1))

            username_list = ", ".join(usernames) if usernames else "None"
            ip_list = ", ".join(ips) if ips else "None"

            brute_force = "Yes" if failed_count > 5 else "No"

            ai_prompt = f"""
You are a cybersecurity assistant.

Respond ONLY in clean bullet points.
No paragraphs.

🔐 Security Summary

• Failed SSH Attempts: {failed_count}
• Successful SSH Logins: {success_count}
• Sudo Activity Count: {sudo_count}
• Suspicious IPs: {ip_list}
• Targeted Usernames: {username_list}
• Brute-force Detected: {brute_force}
• Recommendation: Monitor suspicious IPs and secure SSH access.
"""

            reply = get_ai_response(ai_prompt)

    else:
        # Normal AI Chat
        reply = get_ai_response(user_message)

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