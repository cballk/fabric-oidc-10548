#!/usr/bin/env python3
"""Round 4 (control-only, <=3 logins): validate the auth-mount existence oracle at the ROOT namespace.

Round 2: GET-style mount listing hides aws-iam, but POST /v1/auth/aws-iam/login {} -> 400
"didn't supply required authentication values". To prove that 400/other means "mount exists"
and 404 means "no such mount", send 3 empty POSTs at the root namespace:
  1. random mount name            -> expect 404 no handler (negative control)
  2. jwt-ghwf, empty payload      -> expect 400 (positive control, mount known to exist)
  3. approle, empty payload       -> record 400 (missing role_id) vs 404
Still: no forged signature, no credentials, no role enumeration.
"""
import json
import time
import urllib.error
import urllib.request

BASE = "https://vault.sonar.build"
RND = "zz-ctrl-mount-%d" % (int(time.time()) % 100000)
RESULT = {"probe": "vault-ns-round4-control-12052", "random_mount": RND}


def log(*a):
    print(*a, flush=True)


def http(method, url, data=None, headers=None, timeout=20):
    h = {"User-Agent": "vault-ns-probe4/1.0", "X-Vault-Request": "true"}
    if headers:
        h.update(headers)
    body = json.dumps(data).encode() if data is not None else None
    if body:
        h.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=body, headers=h, method=method)
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return {"status": r.status, "ms": int((time.time() - t0) * 1000), "body": r.read(100000)}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "ms": int((time.time() - t0) * 1000), "body": e.read(100000)}
    except Exception as e:
        return {"status": None, "ms": int((time.time() - t0) * 1000), "error": f"{type(e).__name__}: {str(e)[:200]}"}


def jbody(r):
    try:
        return json.loads(r["body"].decode("utf-8", "replace")) if r.get("body") else None
    except Exception:
        return {"_raw": (r.get("body") or b"")[:300].decode("utf-8", "replace")}


def errs(j):
    if isinstance(j, dict):
        if isinstance(j.get("errors"), list):
            return "; ".join(str(x) for x in j["errors"])[:400]
        if "error" in j:
            return str(j["error"])[:400]
        return json.dumps(j)[:400]
    return str(j)[:400]


def login(mount, payload):
    r = http("POST", f"{BASE}/v1/auth/{mount}/login", data=payload)
    j = jbody(r)
    out = {"mount": mount, "status": r["status"], "ms": r["ms"], "error": r.get("error"),
           "could_not_find_mount": r["status"] == 404}
    if isinstance(j, dict) and isinstance(j.get("auth"), dict):
        out["issued"] = True
        out["token_present"] = bool(j["auth"].get("client_token"))
    else:
        out["resp"] = errs(j) if j is not None else None
    return out


def main():
    RESULT["logins"] = [
        login(RND, {}),
        login("jwt-ghwf", {}),
        login("approle", {}),
    ]
    log("===RESULT_JSON_START===")
    log(json.dumps(RESULT, indent=1, default=str))
    log("===RESULT_JSON_END===")


if __name__ == "__main__":
    main()
