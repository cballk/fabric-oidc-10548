#!/usr/bin/env python3
"""Round 3: where do the KV paths live (root nested-mount path vs namespace) — read-only, bounded.

Round 2 established (same runner plane):
  - sys/internal/ui/mounts is a namespace EXISTENCE oracle:
        existing ns (development / operations / operations/team/re / development/team) -> 200 []
        random ns                                                                    -> 403 permission denied
  - /v1/auth/aws-iam/login with an EMPTY payload in the ROOT namespace -> 400
        "didn't supply required authentication values"  (mount EXISTS in root)
    same empty POST inside any namespace (incl. random) -> 403 permission denied
    (so namespace-scoped auth mounts are not enumerable anonymously at all)
  - no client_token was issued anywhere.

Round 3 sends at most 8 read-only GETs against EXACT paths already known from
facts 12021/12048 (no enumeration), to answer whether those KV paths route in the root
namespace as nested mount paths or only inside a namespace, using the 403 (handler exists,
permission denied) vs 404 "no handler for route" differential. A 200 with data would itself be
an unauthorized read and would be reported. NO writes, NO deletes, NO enumeration.
"""
import json
import time
import urllib.error
import urllib.request

BASE = "https://vault.sonar.build"
RND = "zz-rnd-%d" % (int(time.time()) % 100000)
RESULT = {"probe": "vault-ns-round3-12052", "random": RND}


def log(*a):
    print(*a, flush=True)


def http(method, url, headers=None, timeout=20):
    h = {"User-Agent": "vault-ns-probe3/1.0", "X-Vault-Request": "true"}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, headers=h, method=method)
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return {"status": r.status, "ms": int((time.time() - t0) * 1000), "body": r.read(200000)}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "ms": int((time.time() - t0) * 1000), "body": e.read(200000)}
    except Exception as e:
        return {"status": None, "ms": int((time.time() - t0) * 1000), "error": f"{type(e).__name__}: {str(e)[:200]}"}


def jbody(r):
    try:
        return json.loads(r["body"].decode("utf-8", "replace")) if r.get("body") else None
    except Exception:
        return {"_raw": (r.get("body") or b"")[:400].decode("utf-8", "replace")}


def errs(j):
    if isinstance(j, dict):
        if isinstance(j.get("errors"), list):
            return "; ".join(str(x) for x in j["errors"])[:400]
        if "error" in j:
            return str(j["error"])[:400]
        return json.dumps(j)[:400]
    return str(j)[:400]


def get(path, ns=None, label=""):
    hd = {"X-Vault-Namespace": ns} if ns else {}
    r = http("GET", BASE + "/v1/" + path.lstrip("/"), headers=hd)
    j = jbody(r)
    out = {"label": label, "path": path, "ns": ns, "status": r["status"], "ms": r["ms"],
           "error": r.get("error")}
    if isinstance(j, dict) and isinstance(j.get("data"), dict):
        d = j["data"].get("data") if isinstance(j["data"].get("data"), dict) else j["data"]
        out["data_present"] = True
        out["keys"] = sorted(d.keys())[:20] if isinstance(d, dict) else None
        out["masked_note"] = "unexpected anonymous data - see masked"
        out["masked"] = {k: (str(v)[:4] + "****" + str(v)[-4:] if isinstance(v, str) and len(v) > 8 else "<short>")
                         for k, v in (d.items() if isinstance(d, dict) else [])}
    else:
        out["resp"] = errs(j) if j is not None else None
    return out


def main():
    probes = []
    # exact known paths from facts 12021 / 12048 (no enumeration)
    probes.append(get("development/kv/data/code-security-diff-val-claude-code", None,
                      "known KV path, root routing"))
    probes.append(get("operations/team/re/kv/data/port", None,
                      "known Port KV path, root routing"))
    probes.append(get("development/github/token/aws_platform-sonarcloud-squad_sonarcloud-orchestration-pipeline-lambda-sonarcloud-read",
                      None, "known vended-GitHub-token path, root routing"))
    probes.append(get(f"{RND}/kv/data/x", None, "random control (root)"))
    # namespace-scoped read forms + matching random controls
    probes.append(get("kv/data/port", "operations/team/re", "Port path inside ns=operations/team/re"))
    probes.append(get("kv/data/port", RND, "Port path inside RANDOM ns (control)"))
    probes.append(get("kv/data/code-security-diff-val-claude-code", "development",
                      "known path inside ns=development"))
    probes.append(get("kv/data/x", RND, "random path inside RANDOM ns (control 2)"))
    RESULT["probes"] = probes

    log("===RESULT_JSON_START===")
    log(json.dumps(RESULT, indent=1, default=str))
    log("===RESULT_JSON_END===")
    log("get_count=%d" % len(probes))


if __name__ == "__main__":
    main()
