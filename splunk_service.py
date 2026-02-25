import requests
import urllib3
import time
import re

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SPLUNK_URL = "https://192.168.1.2:8089"
USERNAME = "admin"
PASSWORD = "admin123"

def fetch_failed_logins():

    search_query = 'search source="/var/log/auth.log" "Failed password" | head 20'

    job = requests.post(
        f"{SPLUNK_URL}/services/search/jobs",
        auth=(USERNAME, PASSWORD),
        verify=False,
        data={"search": search_query}
    )

    if job.status_code != 201:
        return "Splunk job creation failed."

    sid = job.json()['sid']

    # Wait for job completion
    while True:
        status = requests.get(
            f"{SPLUNK_URL}/services/search/jobs/{sid}",
            auth=(USERNAME, PASSWORD),
            verify=False,
            params={"output_mode": "json"}
        )

        is_done = status.json()['entry'][0]['content']['isDone']
        if is_done:
            break
        time.sleep(2)

    results = requests.get(
        f"{SPLUNK_URL}/services/search/jobs/{sid}/results",
        auth=(USERNAME, PASSWORD),
        verify=False,
        params={"output_mode": "json"}
    )

    data = results.json()

    logs = []
    for item in data.get("results", []):
        logs.append(item.get("_raw", ""))

    return "\n".join(logs)