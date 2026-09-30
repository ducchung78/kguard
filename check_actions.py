import urllib.request
import json
import time

time.sleep(10)
url = "https://api.github.com/repos/ducchung78/kguard/actions/runs/36707737702/jobs"
req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
try:
    resp = urllib.request.urlopen(req)
    data = json.loads(resp.read().decode())
    for j in data["jobs"]:
        for s in j["steps"]:
            print(f"{s['name']} -> {s['status']} ({s['conclusion']})")
except Exception as e:
    print("Error:", e)
