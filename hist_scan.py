#!/usr/bin/env python3
"""11999: full-history credential scan of SonarSource public repos, run on a GitHub-hosted runner.

For each repo in the requested group:
  1. git clone --bare --filter=blob:limit=200k  (full all-branch history; small blobs fetched upfront)
  2. enumerate every historical blob version with its path across all refs (git log --all --raw)
  3. select tier A (secrets/keys paths), tier B (CI workflows), tier C (deploy/infra configs, C-repos only)
  4. git cat-file --batch every selected blob and regex-grep for credentials
  5. print one RESULT json line per repo (masked samples only) + summary counters
Repo dir is deleted after each repo to keep disk bounded.
"""
import json, os, re, subprocess, sys, time, shutil

BASE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(BASE, 'out')
os.makedirs(OUT, exist_ok=True)

A_RE = r'\.asc$|\.gpg$|\.pgp$|\.key$|\.pem$|\.p12$|\.pfx$|\.jks$|\.keystore$|\.kdbx$|\.ppk$|id_rsa|id_dsa|id_ecdsa|id_ed25519|secring|pubring|keyring|\.tfstate|sops|vault|pgp|gpg|credential|secret|\.env'
TIER_A = re.compile('(?i)(' + A_RE + ')')
TIER_B = re.compile(r'(?i)(\.github/workflows/|jenkinsfile|\.gitlab-ci|\.circleci/|\.buildkite/)')
TIER_C = re.compile(r'(?i)(' + A_RE + r'|token|passw|aws|kms|cloud|deploy|ansible|terraform|tfvars|helm|values[^/]*\.ya?ml$|k8s|kubernetes|docker-compose|dockerfile|\.properties$|application[._]|config[^/]*\.(ya?ml|json|properties|toml|ini)$|\.cfg$|\.ini$)')
EXCL = re.compile(r'(?i)(/l10n/|/locale|i18n|node_modules|/vendor/|third_party|/external/|\.min\.js|testdata|/tests?/|/src/test/|/test-resources/|/examples?/|/samples?/|/fixtures?/)')

C_REPOS = set('''gh-action_release gh-action_releasability gh-action_cache gh-action_aws-s3 gh-action_setup-cloudflare-warp release-github-actions ci-github-actions unified-dogfooding-actions vault-action-wrapper jfrog-setup-wrapper mise-action-wrapper re-vault-plugins sonarqube-mcp-server sonarqube-cli sonar-iac sonar-dummy-gradle-oss sonar-dummy-maven monorepo-project-provisioning core-languages-tooling-public ai-code-assurance-examples getting-started-agentic-analysis-claude-code sonar-scanner-npm sonar-scanner-msbuild sonarlint-core sonarlint-intellij sonarlint-vscode sonarlint-eclipse helm-chart-sonarqube terraform-provider-sonarqube dbd-binaries homebrew-tap'''.split())

CREDRE = [
    ('pgp_fp', re.compile(rb'8EDB ?5BE8|8EDB5BE8D5F9021D|62AF96D0BE7134F1|5674C543E4BEF665')),
    ('anthropic', re.compile(rb'sk-ant-[A-Za-z0-9_\-]{24,}')),
    ('openai_proj', re.compile(rb'sk-proj-[A-Za-z0-9_\-]{24,}')),
    ('openai_classic', re.compile(rb'(?<![A-Za-z0-9])sk-[A-Za-z0-9]{40,}(?![A-Za-z0-9])')),
    ('google_api', re.compile(rb'AIza[0-9A-Za-z_\-]{35}')),
    ('xai', re.compile(rb'(?<![A-Za-z0-9])xai-[A-Za-z0-9]{20,}')),
    ('portkey', re.compile(rb'(?<![A-Za-z0-9])pt-[A-Za-z0-9_\-]{30,}')),
    ('hf', re.compile(rb'hf_[A-Za-z0-9]{30,}')),
    ('aws_akid', re.compile(rb'(?:AKIA|ASIA)[0-9A-Z]{16}')),
    ('aws_secret_assign', re.compile(rb'(?i)aws_?secret_?access_?key\s*[:=]\s*["\']?[A-Za-z0-9/+=]{30,}')),
    ('github_pat', re.compile(rb'gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}')),
    ('sonar_token', re.compile(rb'sq[cup]_[a-z0-9]{20,}')),
    ('vault_token', re.compile(rb'hvs\.[A-Za-z0-9_\-]{20,}')),
    ('slack', re.compile(rb'xox[baprs]-[A-Za-z0-9\-]{10,}')),
    ('pgp_privblock', re.compile(rb'-----BEGIN PGP PRIVATE KEY BLOCK-----')),
    ('ssh_privblock', re.compile(rb'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----')),
    ('gcp_sa', re.compile(rb'"type"\s*:\s*"service_account"')),
    ('kms_arn', re.compile(rb'arn:aws:kms:[a-z0-9\-]+:\d{12}:(?:key|alias)/[A-Za-z0-9/_\-]{3,}')),
    ('sm_ssm_name', re.compile(rb'(?i)(?:secretsmanager|ssm)[^\n]{0,40}(?:vibe-bot/|portkey|anthropic|openai|api[_\-]?key)')),
    ('tf_secret_field', re.compile(rb'(?i)"(?:client_secret|password|api_key|apikey|private_key|secret_key)"\s*:\s*"[^"$]{12,}"')),
]
DEPLOY_PATH = re.compile(r'(?i)(\.tf$|\.tfvars$|tfstate|\.env|\.properties$|values[^/]*\.ya?ml$|\.ya?ml$|\.json$|docker-?compose|\.ini$|\.cfg$|Dockerfile)')
EXTRA = [
    ('plain_secret_assign', re.compile(rb'(?i)(?:password|passwd|secret|api[_-]?key|access[_-]?key|token)\s*[:=]\s*["\'][^"\'$<>\s]{16,}["\']')),
    ('url_creds', re.compile(b'https?://[A-Za-z0-9._%+\\-]{2,40}:[^@/\\s"\']{6,60}@[A-Za-z0-9.\\-]{4,80}')),
    ('pem_field', re.compile(rb'(?i)"(?:private_key|privateKey|key_pem|tls_key|certificate_key)"\s*:\s*"[^"]{40,}"')),
]
NOISE = re.compile(rb'(?i)(example|sample|dummy|placeholder|your[_-]?api|xxx+|test[-_]?key|fake|redacted|xxxxxxxx|<[A-Za-z_][A-Za-z0-9_]*>|\$\{|\$\(|%\(|changeme|not[_-]?a[_-]?real|insert[_-]?|noncompliant|compliant)')


def sh(args, t=1800, inp=None, cwd=None):
    try:
        p = subprocess.run(args, input=inp, capture_output=True, timeout=t, cwd=cwd)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return -9, b'', b'timeout'
    except Exception as e:
        return -1, b'', str(e).encode()


def mask(b, span=70):
    t = b.decode('utf-8', 'ignore')
    return re.sub(r'\s+', ' ', t)[:200]


def scan_repo(repo):
    t0 = time.time()
    d = '/tmp/rs/%s.git' % repo
    shutil.rmtree('/tmp/rs', ignore_errors=True)
    os.makedirs('/tmp/rs', exist_ok=True)
    url = 'https://github.com/SonarSource/%s.git' % repo
    rc = -1; err = b''
    for attempt in range(3):
        rc, out, err = sh(['git', 'clone', '--bare', '--quiet', '--filter=' + os.environ.get('CLONE_FILTER', 'blob:limit=200k'), '--no-single-branch', url, d], t=1500)
        if rc == 0:
            break
        shutil.rmtree(d, ignore_errors=True)
        time.sleep(3 + 3 * attempt)
    res = {'repo': repo}
    if rc != 0:
        res.update({'clone_err': err.decode('utf-8', 'ignore')[:300], 'secs': round(time.time() - t0, 1)})
        return res
    rc, out, err = sh(['git', '-C', d, 'log', '--all', '--raw', '--no-renames', '--format=commit %H', '--no-abbrev'], t=1200)
    if rc != 0:
        res.update({'log_err': err.decode('utf-8', 'ignore')[:300], 'secs': round(time.time() - t0, 1)})
        shutil.rmtree(d, ignore_errors=True)
        return res
    ncommits = out.count(b'\ncommit ') + (1 if out.startswith(b'commit ') else 0)
    cand = {}
    for line in out.split(b'\n'):
        if not line.startswith(b':') or b'\t' not in line:
            continue
        left, path = line[1:].split(b'\t', 1)
        f = left.split(b' ')
        if len(f) < 5:
            continue
        sha = f[3].decode()
        if set(sha) == {'0'}:
            continue
        p = path.decode('utf-8', 'ignore')
        tier = None
        if TIER_A.search(p):
            tier = 'A'
        elif TIER_B.search(p):
            tier = 'B'
        elif TIER_C.search(p) and not EXCL.search(p) and repo in C_REPOS:
            tier = 'C'
        if tier:
            cand.setdefault(sha, []).append((tier, p))
    a = []; b = []; c = []
    for sha, lst in cand.items():
        tiers = {t for t, _ in lst}
        if 'A' in tiers:
            a.append(sha)
        elif 'B' in tiers:
            b.append(sha)
        else:
            c.append(sha)
    b = b[:5000]; c = c[:20000]
    sel = a + b + c
    pm = {s: [p for t, p in cand[s]][:4] for s in sel}
    hits = []; nb = 0; bt = 0; missing = 0; miss_shas = []
    CH = 400
    for k in range(0, len(sel), CH):
        chunk = sel[k:k + CH]
        inp = b''.join(s.encode() + b'\n' for s in chunk)
        prc, pout, perr = sh(['git', '-C', d, 'cat-file', '--batch'], t=1800, inp=inp)
        if prc != 0:
            missing += len(chunk)
            miss_shas.extend(chunk)
            continue
        i = 0; n = len(pout)
        while i < n:
            j = pout.find(b'\n', i)
            if j < 0:
                break
            header = pout[i:j]; i = j + 1
            parts = header.split(b' ')
            if len(parts) < 3:
                missing += 1
                miss_shas.append(header.decode('utf-8', 'ignore').strip())
                continue
            if parts[1] != b'blob':
                continue
            try:
                size = int(parts[2])
            except Exception:
                continue
            content = pout[i:i + size]; i += size + 1
            if size > 20_000_000:
                miss_shas.append(sha)
                continue
            nb += 1; bt += size
            sha = parts[0].decode()
            found = []
            extra = EXTRA if any(DEPLOY_PATH.search(p) for p in (pm.get(sha) or [])) else []
            for name, rx in CREDRE:
                ms = list(rx.finditer(content))
                if not ms:
                    continue
                samples = [mask(content[max(0, m.start() - 70):min(len(content), m.end() + 70)]) for m in ms[:3]]
                found.append({'type': name, 'count': len(ms), 'samples': samples})
            for name, rx in extra:
                ms = list(rx.finditer(content))
                if ms and not any(f['type'] == name for f in found):
                    found.append({'type': 'x_' + name, 'count': len(ms),
                                  'samples': [mask(content[max(0, m.start() - 70):min(len(content), m.end() + 70)]) for m in ms[:3]]})
            if found:
                hits.append({'sha': sha, 'paths': (pm.get(sha) or [])[:3], 'size': size, 'matches': found})
    raw = len(hits)

    def keep(h):
        for m in h['matches']:
            if m['type'] in ('pgp_fp', 'pgp_privblock'):
                return True
            if any(not NOISE.search(x.encode('utf-8', 'ignore')) for x in m['samples']):
                return True
        return False
    hits = [h for h in hits if keep(h)][:40]
    res.update({'commits': ncommits, 'cand_A': len(a), 'cand_B': len(b), 'cand_C': len(c),
                'blobs_read': nb, 'bytes_read': bt, 'missing': missing, 'raw_hits': raw,
                'miss_paths': [p for s2 in miss_shas[:400] for p in (pm.get(s2) or [])][:12],
                'hits': hits, 'secs': round(time.time() - t0, 1)})
    shutil.rmtree(d, ignore_errors=True)
    return res


def main():
    group = sys.argv[1]
    spec = json.load(open(os.path.join(BASE, 'groups.json')))
    repos = spec[group]
    print('GROUP %s repos=%d' % (group, len(repos)), flush=True)
    tot = {'blobs': 0, 'hits': 0, 'errs': 0}
    for i, repo in enumerate(repos):
        try:
            r = scan_repo(repo)
        except Exception as e:
            r = {'repo': repo, 'exc': repr(e)[:300]}
        if 'clone_err' in r or 'log_err' in r or 'exc' in r:
            tot['errs'] += 1
        tot['blobs'] += r.get('blobs_read', 0)
        tot['hits'] += len(r.get('hits') or [])
        print('RESULT ' + json.dumps(r, separators=(',', ':')), flush=True)
        print('PROGRESS %d/%d repo=%s blobs=%d hits=%d tot_blobs=%d tot_hits=%d' % (
            i + 1, len(repos), repo, r.get('blobs_read', 0), len(r.get('hits') or []), tot['blobs'], tot['hits']), flush=True)
        try:
            with open(os.path.join(OUT, group + '.jsonl'), 'a') as f:
                f.write(json.dumps(r) + '\n')
        except Exception:
            pass
    print('GROUP_DONE %s %s' % (group, json.dumps(tot)), flush=True)


if __name__ == '__main__':
    main()
