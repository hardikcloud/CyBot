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

    # Create session if not exists
    if not session_id:
        session_id = create_session(user_message[:30])

    # Save user message
    save_message(session_id, "user", user_message)

    user_lower = user_message.lower()

    # Time detection
    if "yesterday" in user_lower:
        time_range = "yesterday"
    elif "today" in user_lower:
        time_range = "24h"
    elif "7" in user_lower or "week" in user_lower:
        time_range = "7d"
    elif "30" in user_lower or "month" in user_lower:
        time_range = "30d"
    else:
        time_range = "24h"

    # Security query trigger
    if "attack" in user_lower or "ssh" in user_lower or "log" in user_lower:

        logs = fetch_auth_logs(time_range)

        if not logs or isinstance(logs, dict) or len(logs) == 0:
            reply = "No logs found for the selected time range."

        else:
            failed_count = 0
            success_count = 0
            sudo_count = 0
            usernames = set()
            ips = set()

            for line in logs:

                if "Failed password" in line:
                    failed_count += 1

                    invalid_user = re.search(r"invalid user (\w+)", line)
                    normal_user = re.search(r"Failed password for (\w+)", line)

                    if invalid_user:
                        usernames.add(invalid_user.group(1))
                    if normal_user:
                        usernames.add(normal_user.group(1))

                if "Accepted password" in line:
                    success_count += 1
                    success_user = re.search(r"Accepted password for (\w+)", line)
                    if success_user:
                        usernames.add(success_user.group(1))

                if "sudo:" in line:
                    sudo_count += 1
                    sudo_user = re.search(r"sudo:\s+(\w+)", line)
                    if sudo_user:
                        usernames.add(sudo_user.group(1))

                ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
                if ip_match:
                    ips.add(ip_match.group(1))

            username_list = ", ".join(usernames) if usernames else "None"
            ip_list = ", ".join(ips) if ips else "None"
            brute_force = "Yes" if failed_count >= 5 else "No"

            # Attack Type Detection
            if failed_count >= 5:
                attack_type = "SSH Brute Force Attack"
            elif len(usernames) >= 3 and failed_count >= 3:
                attack_type = "Username Enumeration Attempt"
            elif "root" in usernames and success_count > 0:
                attack_type = "Suspicious Root Login"
            else:
                attack_type = "No Major Attack Detected"

            reply = f"""• Attack Type: {attack_type}
• Failed SSH Attempts: {failed_count}
• Successful SSH Logins: {success_count}
• Sudo Activity Count: {sudo_count}
• Suspicious IPs: {ip_list}
• Targeted Usernames: {username_list}
• Brute-force Detected: {brute_force}
• Time Range: {time_range}"""

    else:
        reply = get_ai_response(user_message)

    # Save bot message
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