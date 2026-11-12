#!/usr/bin/env python3
"""11994 run2: per-IP TCP/TLS diagnostics with a positive SonarSource-internal control (vault.sonar.build)."""
import json, os, socket, ssl, time, urllib.request, urllib.error

OPEN = urllib.request.build_opener(urllib.request.ProxyHandler({}))
TARGETS = ["github-enterprise.sonarqube.com", "gitlab-enterprise.sonarqube.com",
           "vault.sonar.build", "example.com"]


def log(*a):
    print(*a, flush=True)


def dns(name):
    try:
        return sorted({i[4][0] for i in socket.getaddrinfo(name, 443, proto=socket.IPPROTO_TCP)})
    except Exception as e:
        return {"error": "%s: %s" % (type(e).__name__, e)}


def tcp(ip, port=443, timeout=6, sni=None):
    r = {"ip": ip, "port": port, "sni": sni}
    t0 = time.time()
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        r["connect_ms"] = round((time.time() - t0) * 1000)
        try:
            ctx = ssl.create_default_context()
            t1 = time.time()
            with ctx.wrap_socket(s, server_hostname=sni) as ss:
                r["tls_ok"] = True
                r["tls_ms"] = round((time.time() - t1) * 1000)
                cert = ss.getpeercert() or {}
                r["cn"] = dict(x[0] for x in cert.get("subject", ())).get("commonName")
        except Exception as e:
            r["tls_ok"] = False
            r["tls_error"] = "%s: %s" % (type(e).__name__, e)
            try:
                s.close()
            except Exception:
                pass
    except Exception as e:
        r["connect_ok"] = False
        r["connect_error"] = "%s: %s" % (type(e).__name__, e)
        r["ms"] = round((time.time() - t0) * 1000)
    return r


def http(url, timeout=15):
    r = {"url": url}
    try:
        with OPEN.open(urllib.request.Request(url, headers={"User-Agent": "probe-11994r2/1.0"}), timeout=timeout) as resp:
            b = resp.read(600)
            r.update(status=resp.status, ms=r.get("ms"), len=len(b), body=b.decode("utf-8", "replace")[:200])
    except urllib.error.HTTPError as e:
        r.update(status=e.code, body=e.read(600).decode("utf-8", "replace")[:200])
    except Exception as e:
        r["error"] = "%s: %s" % (type(e).__name__, e)
    return r


def main():
    ph = {"ts": int(time.time()), "egress": None, "targets": {}}
    try:
        r = http("https://api.ipify.org?format=json", timeout=10)
        ph["egress"] = r.get("body")
    except Exception:
        pass
    log("egress:", ph["egress"])
    for h in TARGETS:
        ips = dns(h)
        entry = {"dns": ips, "tcp": []}
        if isinstance(ips, list):
            for ip in ips[:4]:
                res = tcp(ip, sni=h)
                entry["tcp"].append(res)
        ph["targets"][h] = entry
        mins = [(x.get("ip"), x.get("connect_ok", True), x.get("connect_ms"), x.get("tls_ok"), x.get("connect_error") or x.get("tls_error")) for x in entry["tcp"]]
        log("TCP", h, mins)
    ph["http"] = {}
    for h, p in [("github-enterprise.sonarqube.com", "/api/v3/zen"),
                 ("gitlab-enterprise.sonarqube.com", "/api/v4/version"),
                 ("vault.sonar.build", "/v1/sys/health"),
                 ("example.com", "/")]:
        r = http("https://%s%s" % (h, p), timeout=15)
        ph["http"][h + p] = r
        log("HTTP", h + p, r.get("status"), r.get("error"), (r.get("body") or "")[:80])
    with open("result2.json", "w") as f:
        json.dump(ph, f, indent=1)
    log("===RESULT_JSON_BEGIN===")
    log(json.dumps(ph, indent=1))
    log("===RESULT_JSON_END===")


if __name__ == "__main__":
    main()
