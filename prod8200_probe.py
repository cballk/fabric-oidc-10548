#!/usr/bin/env python3
"""Read-only check: run 43188307906 showed TCP 8200 open on vault.sonar.build A records
(18.198.153.112 / 63.184.0.198) while port 80 timed out.  Determine what listens on 8200:
direct Vault API, same cluster as 443, or something else.  No auth, no login.
"""
import json
import socket
import ssl
import time

IPS = ["18.198.153.112", "63.184.0.198"]
HOSTS = ["vault.sonar.build", "vault-public.sonar.build"]
RESULT = {"probe": "vault-prod-8200-12036", "tcp": {}, "tls": {}, "http": {}}


def tcp(ip, port, tmo=8):
    t0 = time.time()
    try:
        s = socket.create_connection((ip, port), timeout=tmo)
        s.close()
        return {"ok": True, "ms": int((time.time() - t0) * 1000)}
    except Exception as e:
        return {"ok": False, "ms": int((time.time() - t0) * 1000), "err": type(e).__name__}


def tls_info(ip, host, port, tmo=10):
    try:
        ctx = ssl._create_unverified_context()
        raw = socket.create_connection((ip, port), timeout=tmo)
        s = ctx.wrap_socket(raw, server_hostname=host)
        cert = s.getpeercert()
        out = {"version": s.version(), "cipher": s.cipher()[0],
               "subject": cert.get("subject"), "issuer": cert.get("issuer"),
               "san": cert.get("subjectAltName"),
               "notAfter": cert.get("notAfter")}
        s.close()
        return out
    except Exception as e:
        return {"err": f"{type(e).__name__}: {str(e)[:160]}"}


def raw_get(scheme, ip, host, port, path, tmo=12, maxbody=6000):
    hdrs = {"Host": host, "User-Agent": "conn-probe/1.0", "Accept": "*/*",
            "X-Vault-Request": "true", "Connection": "close"}
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
                c = s.recv(4096)
            except socket.timeout:
                break
            if not c:
                break
            buf += c
        head, _, body = buf.partition(b"\r\n\r\n")
        lines = head.decode("latin-1", "replace").split("\r\n")
        st = None
        if lines and lines[0].startswith("HTTP/"):
            try:
                st = int(lines[0].split()[1])
            except Exception:
                pass
        hh = {}
        for ln in lines[1:]:
            if ":" in ln:
                k, v = ln.split(":", 1)
                hh[k.strip().lower()] = v.strip()
        return {"status": st, "ms": int((time.time() - t0) * 1000), "headers": hh,
                "body": body.decode("utf-8", "replace")[:2200]}
    except Exception as e:
        return {"status": None, "ms": int((time.time() - t0) * 1000),
                "err": f"{type(e).__name__}: {str(e)[:140]}"}
    finally:
        if s:
            try:
                s.close()
            except Exception:
                pass


def main():
    for host in HOSTS:
        RESULT["tcp"][host] = {ip: tcp(ip, 8200) for ip in IPS}
        for ip in IPS:
            if not RESULT["tcp"][host][ip]["ok"]:
                continue
            key = f"{host}@{ip}:8200"
            RESULT["tls"][key] = tls_info(ip, host, 8200)
            RESULT["http"][key] = {}
            for path in ["/v1/sys/health", "/v1/sys/seal-status",
                         "/v1/sys/internal/ui/mounts", "/", "/__probe_control_8200"]:
                RESULT["http"][key][path] = raw_get("https", ip, host, 8200, path)
    print("===RESULT_JSON_START===")
    print(json.dumps(RESULT, indent=1, default=str))
    print("===RESULT_JSON_END===")


if __name__ == "__main__":
    main()
