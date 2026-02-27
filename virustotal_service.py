import requests
import time
import base64

API_KEY = "PASTE_NEW_KEY_HERE"

BASE_URL = "https://www.virustotal.com/api/v3"


def scan_url_virustotal(url):

    headers = {
        "x-apikey": '99b887c2e678f549c8ce46dfb3a393b1be3497819e48d30979849685f3e83509'
    }

    url_bytes = url.encode()
    encoded_url = base64.urlsafe_b64encode(url_bytes).decode().strip("=")

    response = requests.get(
        f"{BASE_URL}/urls/{encoded_url}",
        headers=headers
    )

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