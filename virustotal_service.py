import requests
import time
import base64
import os

BASE_URL = "https://www.virustotal.com/api/v3"
API_KEY = os.getenv("VT_API_KEY")

headers = {
    "x-apikey": 'a93b474690f7d84fdb7d63684c2c45424202892d95cd9656d4e7b9a4529a3be9 '
}


# =========================
# URL SCAN
# =========================
def scan_url_virustotal(url):

    url_bytes = url.encode()
    encoded_url = base64.urlsafe_b64encode(url_bytes).decode().strip("=")

    response = requests.get(
        f"{BASE_URL}/urls/{encoded_url}",
        headers=headers
    )

    # If URL not analysed yet → submit first
    if response.status_code == 404:
        submit = requests.post(
            f"{BASE_URL}/urls",
            headers=headers,
            data={"url": url}
        )

        if submit.status_code != 200:
            return {"error": f"Submit failed: {submit.status_code}"}

        time.sleep(5)

        response = requests.get(
            f"{BASE_URL}/urls/{encoded_url}",
            headers=headers
        )

    if response.status_code != 200:
        return {"error": f"Fetch failed: {response.status_code}"}

    stats = response.json()["data"]["attributes"]["last_analysis_stats"]

    return format_stats(stats)


# =========================
# FILE SCAN
# =========================
def scan_file_virustotal(file_path):

    with open(file_path, "rb") as f:
        files = {"file": f}
        upload = requests.post(
            f"{BASE_URL}/files",
            headers=headers,
            files=files
        )

    if upload.status_code != 200:
        return {"error": f"Upload failed: {upload.status_code}"}

    analysis_id = upload.json()["data"]["id"]

    # 🔥 Poll until completed
    for _ in range(15):  # check up to ~15 seconds
        time.sleep(2)

        analysis = requests.get(
            f"{BASE_URL}/analyses/{analysis_id}",
            headers=headers
        )

        if analysis.status_code != 200:
            continue

        data = analysis.json()["data"]
        status = data["attributes"]["status"]

        if status == "completed":
            stats = data["attributes"]["stats"]
            return format_stats(stats)

    return {"error": "Analysis timeout. Try again."}

# =========================
# COMMON RESULT FORMATTER
# =========================
def format_stats(stats):

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)

    status = "safe"

    if malicious > 0:
        status = "malicious"
    elif suspicious > 0:
        status = "suspicious"

    return {
        "status": status,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless
    }