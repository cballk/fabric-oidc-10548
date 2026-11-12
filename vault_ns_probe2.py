#!/usr/bin/env python3
"""Round 2: namespace existence control + aws-iam mount location differential (read-only, bounded).

Round 1 on the same runner-plane showed:
  root namespace  : only auth mount github/ (no secret engines visible)
  ns=development / operations / operations/team/re : HTTP 200 with EMPTY auth+secret lists
  ns=operations/team/re/kv                        : HTTP 403 permission denied
  /v1/sys/internal/ui/mounts/<path> (any)         : HTTP 403 permission denied (not informative)
  /v1/sys/internal/ui/namespaces                  : 500 "client token empty"
  /v1/sys/namespaces                              : 403 permission denied

Because sys/internal/ui/mounts only lists mounts with listing_visibility=unauth, an empty list
does NOT prove absence. Round 2 therefore adds:
  (a) a RANDOM namespace control to decide whether 200-empty vs 403 actually discriminates
      namespace existence, plus X-Vault-Namespace on /v1/sys/health;
  (b) the auth-mount existence oracle that matters: POST /v1/auth/aws-iam/login with an EMPTY
      payload under each candidate namespace (root, development, operations, operations/team/re)
      and one random namespace control. aws-iam answers 400 "missing client request"/similar when
      the mount EXISTS; a missing mount answers 404 "no handler for route". No forged AWS
      signature, no credentials; counted against the global <=10 login budget.
  (c) same empty-POST differential for jwt-ghwf in ns=development (400 missing jwt vs 404).
NO writes, NO deletes, NO role/KV enumeration, NO password injection.
"""
import json
import socket
import time
import urllib.error
import urllib.request

BASE = "https://vault.sonar.build"
RND = "zz-nonexistent-%d" % (int(time.time()) % 100000)
RESULT = {"probe": "vault-ns-round2-12052", "random_ns": RND}
GET_COUNT = 0
LOGIN_COUNT = 0
MAX_LOGINS = 10


def log(*a):
    print(*a, flush=True)


def http(method, url, data=None, headers=None, timeout=20):
    h = {"User-Agent": "vault-ns-probe2/1.0"}
    if headers:
        h.update(headers)
    body = None
    if data is not None:
        body = json.dumps(data).encode()
        h.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=body, headers=h, method=method)
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read(200000)
            return {"status": r.status, "ms": int((time.time() - t0) * 1000), "body": raw}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "ms": int((time.time() - t0) * 1000), "body": e.read(200000)}
    except Exception as e:
        return {"status": None, "ms": int((time.time() - t0) * 1000),
                "error": f"{type(e).__name__}: {str(e)[:200]}"}


def jbody(r):
    try:
        return json.loads(r["body"].decode("utf-8", "replace")) if r.get("body") else None
    except Exception:
        return {"_raw": (r.get("body") or b"")[:600].decode("utf-8", "replace")}


def errs(j):
    if isinstance(j, dict):
        if isinstance(j.get("errors"), list):
            return "; ".join(str(x) for x in j["errors"])[:600]
        if "error" in j:
            return str(j["error"])[:600]
        return json.dumps(j)[:600]
    return str(j)[:600]


def mounts(ns=None, label=""):
    global GET_COUNT
    GET_COUNT += 1
    hd = {"X-Vault-Request": "true"}
    if ns:
        hd["X-Vault-Namespace"] = ns
    r = http("GET", BASE + "/v1/sys/internal/ui/mounts", headers=hd)
    j = jbody(r)
    out = {"label": label, "ns": ns, "status": r["status"], "ms": r["ms"],
           "error": r.get("error")}
    if isinstance(j, dict) and isinstance(j.get("data"), dict):
        out["auth_keys"] = sorted((j["data"].get("auth") or {}).keys())
        out["secret_keys"] = sorted((j["data"].get("secret") or {}).keys())
        out["auth_types"] = {k: (v or {}).get("type") for k, v in (j["data"].get("auth") or {}).items()}
    else:
        out["resp"] = errs(j) if j is not None else None
    return out


def health_ns(ns):
    global GET_COUNT
    GET_COUNT += 1
    r = http("GET", BASE + "/v1/sys/health?standbyok=true&perfstandbyok=true",
             headers={"X-Vault-Namespace": ns})
    j = jbody(r)
    out = {"ns": ns, "status": r["status"], "ms": r["ms"], "error": r.get("error")}
    if isinstance(j, dict):
        out["version"] = j.get("version")
        out["cluster_name"] = j.get("cluster_name")
        out["initialized"] = j.get("initialized")
    out["resp"] = None if out.get("version") else errs(j)
    return out


def login(mount, payload, ns=None, label=""):
    global LOGIN_COUNT
    if LOGIN_COUNT >= MAX_LOGINS:
        return {"label": label, "skipped": "login budget exhausted"}
    LOGIN_COUNT += 1
    hd = {"X-Vault-Request": "true"}
    if ns:
        hd["X-Vault-Namespace"] = ns
    r = http("POST", f"{BASE}/v1/auth/{mount}/login", data=payload, headers=hd)
    j = jbody(r)
    out = {"label": label, "mount": mount, "ns": ns, "status": r["status"], "ms": r["ms"],
           "error": r.get("error"), "payload_keys": sorted(payload.keys())}
    if isinstance(j, dict):
        if isinstance(j.get("auth"), dict):
            out["issued"] = True
            out["token_present"] = bool(j["auth"].get("client_token"))
            if j["auth"].get("client_token"):
                out["_client_token"] = j["auth"]["client_token"]
        else:
            out["resp"] = errs(j)
    return out


def main():
    m = []
    m.append(mounts(None, "root-control"))
    m.append(mounts("development", "ns=development"))
    m.append(mounts("operations", "ns=operations"))
    m.append(mounts("operations/team/re", "ns=operations/team/re"))
    m.append(mounts(RND, "ns=RANDOM-control"))
    m.append(mounts("development/team", "ns=development/team control"))
    RESULT["ui_mounts"] = m
    RESULT["health_ns"] = [health_ns("development"), health_ns("operations/team/re"), health_ns(RND)]

    # aws-iam existence oracle: empty POST per candidate namespace + random control
    lg = []
    for ns in (None, "development", "operations", "operations/team/re"):
        lg.append(login("aws-iam", {}, ns, f"aws-iam:empty ns={ns}"))
    lg.append(login("aws-iam", {}, RND, f"aws-iam:empty ns=RANDOM"))
    # jwt-ghwf in the development namespace (empty payload -> 400 missing jwt if mount exists)
    lg.append(login("jwt-ghwf", {}, "development", "jwt-ghwf:empty ns=development"))
    # a second likely mount name under development (approle) with empty payload
    lg.append(login("approle", {}, "development", "approle:empty ns=development"))
    RESULT["logins"] = lg

    issued = None
    issued_ns = None
    for it in lg:
        if it.get("_client_token"):
            issued = it.pop("_client_token")
            issued_ns = it.get("ns")
            break
    RESULT["token_issued"] = bool(issued)

    log("===RESULT_JSON_START===")
    log(json.dumps(RESULT, indent=1, default=str))
    log("===RESULT_JSON_END===")
    log(f"budget: GET_COUNT={GET_COUNT} LOGIN_COUNT={LOGIN_COUNT}")


if __name__ == "__main__":
    main()
