import os, json, base64, urllib.request, urllib.parse, urllib.error, sys

FABRIC = "https://fabric-prod1.defang.dev/io.defang.v1.FabricController"

def get_token(aud=None):
    url = os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"]
    if aud:
        url += "&audience=" + urllib.parse.quote(aud, safe="")
    req = urllib.request.Request(url, headers={"Authorization": "bearer " + os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)["value"]

def call(method, body, token=None):
    req = urllib.request.Request(FABRIC + "/" + method, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json", "Connect-Protocol-Version": "1"})
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()
    except Exception as e:
        return -1, repr(e)

def claims(t):
    p = t.split(".")[1]
    p += "=" * (-len(p) % 4)
    c = json.loads(base64.urlsafe_b64decode(p))
    ks = ["iss","sub","aud","ref","environment","repository","repository_owner","repository_owner_id","job_workflow_ref","event_name","workflow","actor"]
    return {k: c.get(k) for k in ks}

AUDIENCES = [None, "https://github.com/DefangLabs", "https://github.com/defangdevs", "https://github.com/cballk", "https://fabric-prod1.defang.dev"]
for aud in AUDIENCES:
    print("===== audience=%r" % (aud if aud else "<default>"), flush=True)
    try:
        t = get_token(aud)
    except Exception as e:
        print("GET TOKEN FAIL", repr(e)); continue
    print("tokenlen=%d" % len(t), flush=True)
    print("claims=" + json.dumps(claims(t)), flush=True)
    tenants = [None]
    if aud in (None, "https://github.com/DefangLabs", "https://github.com/defangdevs"):
        tenants += ["defangdevs", "cballk"]
    for ten in tenants:
        body = {"assertion": t, "scope": ["admin","read","delete","tail"]}
        if ten: body["tenant"] = ten
        st, resp = call("Token", body)
        print("-- Token tenant=%r -> HTTP %s %s" % (ten, st, resp[:600]), flush=True)
        try:
            at = json.loads(resp).get("accessToken")
        except Exception:
            at = None
        if at:
            p = at.split(".")[1]; p += "=" * (-len(p) % 4)
            print("   fabric-token-claims=" + json.dumps(json.loads(base64.urlsafe_b64decode(p))), flush=True)
            for m in ("WhoAmI", "ListStacks", "ListProjects", "GetStatus", "GetVersion"):
                st2, r2 = call(m, {}, at)
                print("   %s -> %s %s" % (m, st2, r2[:300]), flush=True)
print("DONE")
