import requests
import urllib3
import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SPLUNK_URL = "https://192.168.1.13:8089"
USERNAME = "admin"
PASSWORD = "admin123"
def fetch_failed_logins():

    search_query = 'search source="/var/log/auth.log" "Failed password" | head 20'

    # STEP 1 — Create Search Job
    job = requests.post(
        f"{SPLUNK_URL}/services/search/jobs",
        auth=(USERNAME, PASSWORD),
        verify=False,
        data={
            "search": search_query,
            "output_mode": "json"
        }
    )

    if job.status_code != 201:
        print("Job Creation Failed:", job.text)
        return {"error": "Splunk job creation failed."}

    try:
        sid = job.json().get("sid")
    except Exception as e:
        print("JSON Error:", job.text)
        return {"error": "Invalid JSON from Splunk."}

    # STEP 2 — Wait for completion (max 20 sec)
    for _ in range(10):
        status = requests.get(
            f"{SPLUNK_URL}/services/search/jobs/{sid}",
            auth=(USERNAME, PASSWORD),
            verify=False,
            params={"output_mode": "json"}
        )

        if status.status_code != 200:
            return {"error": "Failed to check job status."}

        is_done = status.json()['entry'][0]['content']['isDone']

        if is_done:
            break

        time.sleep(2)

    # STEP 3 — Fetch results
    results = requests.get(
        f"{SPLUNK_URL}/services/search/jobs/{sid}/results",
        auth=(USERNAME, PASSWORD),
        verify=False,
        params={"output_mode": "json"}
    )

    if results.status_code != 200:
        return {"error": "Failed to fetch results."}

    data = results.json()
    logs = [item.get("_raw", "") for item in data.get("results", [])]

    return logs