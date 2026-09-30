import urllib.request
import json

url = "https://api.github.com/repos/ducchung78/kguard/actions/jobs/36707365503/logs"
# Wait, GitHub job logs are at: https://api.github.com/repos/{owner}/{repo}/actions/jobs/{job_id}/logs
# Let's get the job_id first:
jobs_url = "https://api.github.com/repos/ducchung78/kguard/actions/runs/36707365503/jobs"
req = urllib.request.Request(jobs_url, headers={"User-Agent": "Mozilla/5.0"})
data = json.loads(urllib.request.urlopen(req).read().decode())
job_id = data["jobs"][0]["id"]
print("Job ID:", job_id)

try:
    log_url = f"https://api.github.com/repos/ducchung78/kguard/actions/jobs/{job_id}/logs"
    req_log = urllib.request.Request(log_url, headers={"User-Agent": "Mozilla/5.0"})
    log_content = urllib.request.urlopen(req_log).read().decode(errors="replace")
    for line in log_content.splitlines():
        if "error:" in line.lower() or "failed" in line.lower() or "fatal" in line.lower() or "ndk-build" in line:
            print(line)
except Exception as e:
    print("Log fetch error:", e)
