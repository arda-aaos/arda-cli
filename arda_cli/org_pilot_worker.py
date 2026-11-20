#!/usr/bin/env python3
"""Ubuntu: one-repository GitHub organization pilot, fail closed, no AOSP writes."""
from __future__ import annotations
import json, re, subprocess, sys, time, urllib.parse
from pathlib import Path

NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,78}[A-Za-z0-9]$|[A-Za-z0-9]$")
SHA = re.compile(r'[a-f0-9]{40}$')
EXCLUDED = {'arda-aaos-manifest', 'arda-releases', 'ArdaPlatform',
            'android_device_brcm_rpi4', 'android_device_brcm_rpi5',
            'android_vendor_arda', 'android_vendor_arda_ardaplatform',
            'arda-aaos-proprietary', 'arda-aaos-vendor'}

class Stop(Exception): pass

def checked_name(v):
    if not isinstance(v,str) or not NAME.fullmatch(v) or '..' in v or v.startswith('.') or v.endswith('.'):
        raise Stop('Invalid repository/organization name')
    return v

def gh(*args, timeout=45):
    try:
        p=subprocess.run(['gh',*args],capture_output=True,text=True,errors='replace',timeout=timeout)
    except (OSError,subprocess.TimeoutExpired):raise Stop('GitHub CLI unavailable or timed out') from None
    return p

def http_status_from_gh_stderr(stderr):
    """Extract an explicit GitHub CLI HTTP status, never guess from JSON body.

    GitHub CLI emits e.g. 'gh: Not Found (HTTP 404)', not just
    'HTTP 404:' or '404 Not Found'. Absence of a status is NOT a 404.
    """
    for line in stderr.splitlines():
        m=re.search(r'\bHTTP[ /]+(\d{3})\b',line,re.I)
        if m:return int(m.group(1))
    return None

def api(endpoint,allow_404=False):
    p=gh('api',endpoint)
    if p.returncode:
        code=http_status_from_gh_stderr(p.stderr)
        if allow_404 and code==404:return None
        detail=f'HTTP {code}' if code is not None else 'no verified HTTP status (network/auth/transport error)'
        raise Stop('GitHub API read-only lookup failed for '+endpoint+' ['+detail+']; no automatic retry')
    try:r=json.loads(p.stdout)
    except ValueError:raise Stop('Invalid GitHub API response: '+endpoint)
    if not isinstance(r,dict):raise Stop('Unexpected GitHub response shape')
    return r

def head(owner,repo,branch):
    endpoint='repos/'+owner+'/'+repo+'/commits/'+urllib.parse.quote(branch,safe='')
    rec=api(endpoint)
    sha=rec.get('sha')
    if not isinstance(sha,str) or not SHA.fullmatch(sha):raise Stop('Missing/invalid default branch HEAD')
    return sha

def existing_xml_refs(root, repo):
    """Conservative dependency hints, not a complete dependency proof."""
    base=Path(root)
    files=[]
    local=base/'.repo/local_manifests'
    if local.is_dir():files+=sorted(local.glob('*.xml'))
    maindir=base/'.repo/manifests'
    if maindir.is_dir():files+=sorted(maindir.glob('*.xml'))
    manifest=base/'.repo/manifest.xml'
    if manifest.is_file():files.append(manifest)
    matched=[]
    for fp in files[:250]:
        try:
            body=fp.read_text('utf8')
        except (OSError,UnicodeError):continue
        if re.search(r'(?<![A-Za-z0-9_.-])'+re.escape(repo)+r'(?![A-Za-z0-9_.-])',body,re.I):
            matched.append(str(fp.relative_to(base)))
    return sorted(set(matched))

def preflight(payload):
    repo=checked_name(payload['repo'])
    target=checked_name(payload['target'])
    if target.casefold()=='deadknight':raise Stop('Source and target owners must differ')
    actor=api('user')
    if actor.get('login','').casefold()!='deadknight':raise Stop('Expected Deadknight gh account')
    org=api('orgs/'+target)
    if org.get('login','').casefold()!=target.casefold():raise Stop('Target organization identity mismatch')
    membership=api('user/memberships/orgs/'+target)
    if membership.get('state')!='active' or membership.get('role')!='admin':
        raise Stop('Organization active admin membership required')
    src=api('repos/Deadknight/'+repo)
    if src.get('full_name','').casefold()!=('Deadknight/'+repo).casefold():
        raise Stop('Source path redirects or is no longer owned by Deadknight')
    if not src.get('permissions',{}).get('admin',False):raise Stop('Source repo admin permission not verified')
    dest=api('repos/'+target+'/'+repo,allow_404=True)
    if dest is not None:raise Stop('Destination repo already exists or source already transferred')
    private=bool(src.get('private'))
    if private:raise Stop('Private repositories excluded from pilot migration')
    if src.get('archived',False):raise Stop('Archived repo excluded from pilot migration')
    if repo in EXCLUDED:raise Stop('Critical ARDA repo excluded from pilot migration')
    if src.get('fork',False):raise Stop('Fork-network repo excluded from first pilot migration')
    branch=src.get('default_branch')
    if not isinstance(branch,str) or not branch:raise Stop('No default branch; empty repo not suitable for SHA pilot')
    sha=head('Deadknight',repo,branch)
    refs=existing_xml_refs(payload['root'],repo)
    if refs:raise Stop('Repository referenced by AOSP manifest; excluded from first pilot ('+', '.join(refs)+')')
    rid=src.get('id')
    if not isinstance(rid,int) or rid<=0:raise Stop('Invalid repository ID')
    return {'source':'Deadknight/'+repo,'target':target+'/'+repo,'repository_id':rid,
            'default_branch':branch,'source_head':sha,'visibility':src.get('visibility','public'),
            'private':private,'fork':False,'aosp_manifest_refs':refs,
            'actor':actor.get('login'),'membership':'admin / active',
            'decision':'READY_PILOT' }

def transfer(payload):
    before=preflight(payload)
    expected=payload.get('expected')
    if not isinstance(expected,dict):raise Stop('Prior plan snapshot missing; run pilot --plan first')
    for field in ('source','target','repository_id','default_branch','source_head','visibility'):
        if before[field]!=expected.get(field):raise Stop('Plan stale ('+field+'); no transfer')
    if payload.get('confirm')!=before['source']+' -> '+before['target']:
        raise Stop('Exact --confirm string required; no transfer')
    repo=checked_name(payload['repo']);target=checked_name(payload['target'])
    post=gh('api','-X','POST','repos/Deadknight/'+repo+'/transfer','-f','new_owner='+target,timeout=100)
    if post.returncode:
        # Network errors can occur after GitHub accepted a request. Never auto-retry.
        return {'status':'REQUEST_OUTCOME_UNKNOWN_CHECK_GITHUB',
                'transferred_request_sent':True,'preflight':before,
                'warning':'Transfer API returned an error or lost connection; inspect GitHub before any retry'}
    # A 202 response can arrive before final ownership changes. Never repeat transfer automatically.
    after={'status':'REQUEST_ACCEPTED_VERIFICATION_PENDING','transferred_request_sent':True, 'preflight':before}
    for i in range(4):
        if i:time.sleep(2)
        try:
            dest=api('repos/'+target+'/'+repo,allow_404=True)
            if dest is None:continue
            if dest.get('id')!=before['repository_id'] or dest.get('full_name','').casefold()!=before['target'].casefold():
                raise Stop('Transferred repo identity mismatch; manual review needed')
            if bool(dest.get('private'))!=before['private']:
                raise Stop('Visibility changed during transfer; manual review needed')
            actual=head(target,repo,before['default_branch'])
            if actual!=before['source_head']:raise Stop('Transferred repo HEAD changed; manual review needed')
            after.update({'status':'TRANSFER_VERIFIED','target_head':actual,'repository_id':dest['id']})
            break
        except Stop as e:
            after['verify_warning']=str(e)
            # if destination appeared with incompatible data, do not retry or overwrite
            if 'identity mismatch' in str(e) or 'Visibility changed' in str(e) or 'HEAD changed' in str(e):break
    return after

def main():
    payload=json.loads(sys.stdin.read())
    result=transfer(payload) if payload.get('apply') else {'status':'PLAN_ONLY','transferred_request_sent':False,'preflight':preflight(payload)}
    return result

if __name__=='__main__':
    try:
        print(json.dumps(main(),sort_keys=True,ensure_ascii=False))
    except Exception as e:
        print(json.dumps({'status':'STOP','error':str(e)[:400],'transfer_may_have_been_requested':False},sort_keys=True))
        sys.exit(3)
