import urllib.request
import os
import zipfile
import subprocess

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
DIST_DIR = os.path.join(PROJECT_ROOT, "dist")
os.makedirs(DIST_DIR, exist_ok=True)

# 1. Get token from git credential
proc = subprocess.Popen(['git', 'credential', 'fill'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
stdout, _ = proc.communicate("protocol=https\nhost=github.com\n")
token = None
for line in stdout.splitlines():
    if line.startswith("password="):
        token = line.split("=", 1)[1].strip()

print("Got token:", bool(token))

headers = {
    "User-Agent": "Mozilla/5.0",
}
if token:
    headers["Authorization"] = f"Bearer {token}"

def download_artifact(artifact_id, out_name):
    url = f"https://api.github.com/repos/ducchung78/kguard/actions/artifacts/{artifact_id}/zip"
    req = urllib.request.Request(url, headers=headers)
    
    # Custom redirect handler to avoid sending Auth header to S3
    class NoAuthRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, hdrs, newurl):
            new_req = super().redirect_request(req, fp, code, msg, hdrs, newurl)
            if new_req:
                new_req.headers.pop("Authorization", None)
                new_req.headers.pop("authorization", None)
                new_req.unredirected_hdrs.pop("Authorization", None)
                new_req.unredirected_hdrs.pop("authorization", None)
            return new_req

    opener = urllib.request.build_opener(NoAuthRedirect)
    out_path = os.path.join(DIST_DIR, out_name)
    print(f"Downloading {url} to {out_path}...")
    with opener.open(req) as resp, open(out_path, "wb") as f:
        f.write(resp.read())
    print(f"Saved {out_path} ({os.path.getsize(out_path)} bytes)")
    return out_path

# Download KGuard-SM8550-Release
zip_path = download_artifact(11092188855, "KGuard-SM8550-Release.zip")

# Download kguard-detect-binary
detect_zip = download_artifact(11092109101, "kguard-detect-artifact.zip")

# Unpack KGuard-SM8550-Release.zip (GitHub actions artifact wraps the inner file)
with zipfile.ZipFile(zip_path, 'r') as z:
    z.extractall(DIST_DIR)
    print("Extracted artifact contents:", z.namelist())

with zipfile.ZipFile(detect_zip, 'r') as z:
    z.extractall(DIST_DIR)
    print("Extracted detect artifact:", z.namelist())

print("Artifact extraction complete!")
