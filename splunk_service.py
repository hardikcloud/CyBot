import requests
import urllib3
import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SPLUNK_URL = "https://192.168.1.13:8089"
USERNAME = "admin"
PASSWORD = "admin123"


def run_splunk_search(search_query):

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
        return {"error": "Splunk job creation failed."}

    sid = job.json().get("sid")

    # Wait for job completion
    for _ in range(10):
        status = requests.get(
            f"{SPLUNK_URL}/services/search/jobs/{sid}",
            auth=(USERNAME, PASSWORD),
            verify=False,
            params={"output_mode": "json"}
        )

        if status.status_code != 200:
            return {"error": "Failed to check job status."}

        if status.json()['entry'][0]['content']['isDone']:
            break

        time.sleep(2)

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


def fetch_auth_logs():
    search_query = '''
    search source="/var/log/auth.log"
    ("Failed password" OR "Accepted password" OR "sudo:")
    | head 200
    '''

    return run_splunk_search(search_query)