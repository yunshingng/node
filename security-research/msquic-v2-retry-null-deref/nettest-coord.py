#!/usr/bin/env python3
"""Small GitHub Contents-API rendezvous helper for isolated multi-runner tests."""
import base64, json, os, pathlib, sys, time, urllib.error, urllib.parse, urllib.request

REPO = os.environ.get("GITHUB_REPOSITORY", "yunshingng/node")
TOKEN = os.environ["GITHUB_TOKEN"]
BRANCH = os.environ.get("COORD_BRANCH", "security-research/msquic-offpath-nettest-coordination")
RUN_ID = os.environ["GITHUB_RUN_ID"] + "-" + os.environ.get("GITHUB_RUN_ATTEMPT", "1")
ROOT = f"security-research/msquic-offpath-nettest/{RUN_ID}"

def request(url, data=None, method=None):
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {TOKEN}",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "msquic-offpath-validation",
    }
    body = None if data is None else json.dumps(data).encode()
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    return urllib.request.urlopen(req, timeout=20)

def publish(name, source):
    path = f"{ROOT}/{name}"
    url = f"https://api.github.com/repos/{REPO}/contents/{path}"
    content = pathlib.Path(source).read_bytes()
    payload = {
        "message": f"Publish isolated off-path test rendezvous {RUN_ID}/{name}",
        "content": base64.b64encode(content).decode(),
        "branch": BRANCH,
    }
    with request(url, payload, "PUT") as r:
        print(f"PUBLISHED={path} status={r.status}", flush=True)

def wait_file(name, output, timeout=300):
    path = f"{ROOT}/{name}"
    branch = urllib.parse.quote(BRANCH, safe="")
    url = f"https://api.github.com/repos/{REPO}/contents/{path}?ref={branch}"
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            with request(url) as r:
                item = json.loads(r.read())
            data = base64.b64decode(item["content"])
            pathlib.Path(output).write_bytes(data)
            print(f"RECEIVED={path} bytes={len(data)}", flush=True)
            return
        except Exception as e:
            last = e
            time.sleep(2)
    raise SystemExit(f"TIMEOUT waiting for {path}: {last}")

if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "publish":
        publish(sys.argv[2], sys.argv[3])
    elif len(sys.argv) in (4, 5) and sys.argv[1] == "wait":
        timeout = int(sys.argv[4]) if len(sys.argv) == 5 else 300
        wait_file(sys.argv[2], sys.argv[3], timeout)
    else:
        raise SystemExit("usage: nettest-coord.py publish <name> <local-file> | wait <name> <local-file> [timeout-seconds]")
