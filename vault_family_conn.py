#!/usr/bin/env python3
"""Supplementary read-only connectivity probe: are the dev/staging Vault hosts blackholed
at the TCP layer (all ports) or only ALB 443?  Also try every recorded A record.

Only TCP connect + read-only GET /v1/sys/health on whatever connects. No auth, no login.
"""
import json, os, socket, ssl, time, urllib.request, urllib.error

RECORDED = {
    "vault.sonar.build": ["18.198.153.112", "63.184.0.198"],
    "vault-public.sonar.build": ["35.156.3.249", "18.198.153.112"],
    "vault.dev.sonar.build": ["63.187.38.147", "18.197.139.205", "18.197.82.184", "63.187.220.228"],
    "vault-public.dev.sonar.build": ["18.197.139.205", "63.187.220.228"],
    "vault.staging.sonar.build": ["3.121.195.183", "18.156.79.179"],
    "vault-public.staging.sonar.build": ["3.125.135.87", "18.157.125.57"],
}
PORTS = [443, 8200, 80]
RESULT = {"probe": "vault-family-connectivity-11983b"}


def tcp(ip, port, tmo=6):
    t0 = time.time()
    try:
        s = socket.create_connection((ip, port), timeout=tmo)
        s.close()
        return {"ok": True, "ms": int((time.time() - t0) * 1000)}
    except Exception as e:
        return {"ok": False, "ms": int((time.time() - t0) * 1000), "err": f"{type(e).__name__}: {str(e)[:90]}"}


def https_health(host, tmo=8):
    url = f"https://{host}/v1/sys/health"
    req = urllib.request.Request(url, headers={"User-Agent": "conn-probe/1.0"})
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=tmo) as r:
            b = r.read(2000)
            return {"status": r.status, "ms": int((time.time() - t0) * 1000),
                    "body": json.loads(b.decode("utf-8", "replace")) if b else None}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "ms": int((time.time() - t0) * 1000), "err": "HTTPError"}
    except Exception as e:
        return {"status": None, "ms": int((time.time() - t0) * 1000), "err": f"{type(e).__name__}: {str(e)[:120]}"}


def main():
    # DNS as the runner sees it
    dns = {}
    for host in RECORDED:
        try:
            dns[host] = sorted({i[4][0] for i in socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)})
        except Exception as e:
            dns[host] = [f"ERR {type(e).__name__}: {str(e)[:80]}"]
    RESULT["dns_runner"] = dns

    conn = {}
    for host, ips in RECORDED.items():
        conn[host] = {}
        allips = sorted(set([i for i in ips] + [i for i in dns.get(host, []) if i.count(".") == 3]))
        for ip in allips:
            conn[host][ip] = {str(p): tcp(ip, p) for p in PORTS}
    RESULT["tcp"] = conn

    health = {}
    for host in RECORDED:
        health[host] = https_health(host)
    RESULT["https_health"] = health

    print("===RESULT_JSON_START===")
    print(json.dumps(RESULT, indent=1, default=str))
    print("===RESULT_JSON_END===")


if __name__ == "__main__":
    main()
