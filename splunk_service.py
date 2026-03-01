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

    # Wait until job completes
    for _ in range(15):
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

        time.sleep(1)

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


def fetch_auth_logs(time_range="24h"):

    # 🔥 Proper Time Filters
    if time_range == "24h":
        # Today from midnight
        time_filter = "earliest=@d"

    elif time_range == "yesterday":
        time_filter = "earliest=-1d@d latest=@d"

    elif time_range == "7d":
        time_filter = "earliest=-7d"

    elif time_range == "30d":
        time_filter = "earliest=-30d"

    else:
        # Safe fallback
        time_filter = "earliest=@d"

    search_query = f"""
    search {time_filter} source="/var/log/auth.log"
    ("Failed password" OR "Accepted password" OR "sudo:")
    | sort -_time
    | head 500
    """

    return run_splunk_search(search_query)