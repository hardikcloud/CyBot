import requests
import time
import base64
import os
from dotenv import load_dotenv
load_dotenv()

API_KEY = os.getenv("VT_API_KEY")

BASE_URL = "https://www.virustotal.com/api/v3"


def scan_url_virustotal(url):

    headers = {"x-apikey": API_KEY}

    url_bytes = url.encode()
    encoded_url = base64.urlsafe_b64encode(url_bytes).decode().strip("=")

    response = requests.get(
        f"{BASE_URL}/urls/{encoded_url}",
        headers=headers
    )

    if response.status_code == 404:

        requests.post(
            f"{BASE_URL}/urls",
            headers=headers,
            data={"url": url}
        )

        time.sleep(5)

        response = requests.get(
            f"{BASE_URL}/urls/{encoded_url}",
            headers=headers
        )

    stats = response.json()["data"]["attributes"]["last_analysis_stats"]

    malicious = stats.get("malicious",0)
    suspicious = stats.get("suspicious",0)
    harmless = stats.get("harmless",0)

    status="safe"

    if malicious>0:
        status="malicious"

    elif suspicious>0:
        status="suspicious"

    return{
        "status":status,
        "malicious":malicious,
        "suspicious":suspicious,
        "harmless":harmless
    }


def scan_file_virustotal(file):

    headers = {"x-apikey": API_KEY}

    files = {"file": (file.filename, file.read())}

    try:
        # Upload file
        response = requests.post(
            f"{BASE_URL}/files",
            headers=headers,
            files=files
        )

        if response.status_code not in [200, 201]:
            return {"error": f"file upload failed ({response.status_code})"}

        analysis_id = response.json()["data"]["id"]

        # Poll analysis status
        for _ in range(10):

            time.sleep(4)

            report = requests.get(
                f"{BASE_URL}/analyses/{analysis_id}",
                headers=headers
            )

            if report.status_code != 200:
                continue

            data = report.json()

            if data["data"]["attributes"]["status"] == "completed":

                stats = data["data"]["attributes"]["stats"]

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

        return {"error": "analysis timeout"}

    except Exception as e:
        return {"error": str(e)}