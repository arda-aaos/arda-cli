#!/usr/bin/env python3
"""Ubuntu-side public-core transfer worker (self-contained, no AOSP source writes).

Metadata preflight and single repo transfer+exact Git config migration. Active XML
manifests are not edited. Never retry a GitHub transfer after an ambiguous result.
"""
from __future__ import annotations
import json, re, subprocess, sys, time, urllib.parse
from pathlib import Path

SHA=re.compile(r'^[0-9a-f]{40}$')
NAME=re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,90}$')
KEY=re.compile(r'^remote\.[A-Za-z0-9_.-]+\.url$')
class Stop(Exception):pass

def check(ok,msg):
    if not ok:raise Stop(msg)

def proc(cmd, timeout=45):
    try:
        return subprocess.run(cmd,stdin=subprocess.DEVNULL,capture_output=True,text=True,
                              timeout=timeout,errors='replace')
    except (OSError,subprocess.TimeoutExpired):raise Stop('Command unavailable/timeout; outcome may be uncertain') from None

def json_api(endpoint, missing_ok=False):
    p=proc(['gh','api',endpoint],timeout=60)
    if p.returncode:
        http=re.search(r'\bHTTP[ /]+(\d{3})\b',p.stderr,re.I)
        if missing_ok and http and http.group(1)=='404':return None
        raise Stop('GitHub API check failed; no verified HTTP 404: '+endpoint)
    try:result=json.loads(p.stdout)
    except ValueError:raise Stop('Invalid GitHub API response') from None
    check(isinstance(result,dict),'Unexpected GitHub API response')
    return result

def branch_sha(owner,repo,branch):
    rec=json_api('repos/'+owner+'/'+repo+'/commits/'+urllib.parse.quote(branch,safe=''))
    sha=rec.get('sha')
    check(isinstance(sha,str) and SHA.fullmatch(sha) is not None,'Invalid GitHub branch SHA')
    return sha

def gh_access(target):
    actor=json_api('user')
    membership=json_api('user/memberships/orgs/'+target)
    check(actor.get('login','').casefold()=='deadknight','Expected Ubuntu gh actor Deadknight')
    check(membership.get('state')=='active' and membership.get('role')=='admin',
          'Active organization administrator required')

def read_git_value(fp,key):
    p=proc(['git','config','--file',str(fp),'--get',key],timeout=12)
    check(p.returncode in (0,1),'Git config read failed')
    return p.stdout.strip() if p.returncode==0 else None

def allowed_urls(repo,target):
    return [
        (f'https://github.com/Deadknight/{repo}',f'https://github.com/{target}/{repo}'),
        (f'git@github.com:Deadknight/{repo}',f'git@github.com:{target}/{repo}'),
        (f'ssh://git@github.com/Deadknight/{repo}',f'ssh://git@github.com/{target}/{repo}'),
    ]

def remote_changes(root,target,row):
    repo=row['name'];res=[]
    for r in row.get('git_remotes',[]):
        check(isinstance(r,dict) and r.get('owner')=='SOURCE','Non-source Git remote in frozen plan')
        rel=r.get('file','');key=r.get('remote','')
        check(isinstance(rel,str) and rel.startswith('.repo/projects/') and rel.endswith('/config')
              and '..' not in Path(rel).parts and isinstance(key,str) and KEY.fullmatch(key),
              'Unsafe Git config record')
        fp=root/rel
        check(fp.is_file() and not fp.is_symlink() and fp.resolve().is_relative_to(root.resolve()),
              'Git config not safely located inside AOSP root')
        current=read_git_value(fp,key)
        expected=None;new=None
        for src,dst in allowed_urls(repo,target):
            for suffix in ('','.git'):
                if current==src+suffix:expected=current;new=dst+suffix
        check(expected is not None,'Unexpected Git remote URL for '+repo+' / '+rel+' / '+key)
        res.append({'file':rel,'key':key,'old':expected,'new':new})
    return res

def preflight(payload):
    root=Path(payload['root']);target=payload['target'];row=payload['row'];repo=row['name']
    check(root.is_absolute() and root.is_dir() and (root/'.repo').is_dir(),'AOSP root missing')
    check(NAME.fullmatch(target) and target.casefold()!='deadknight' and NAME.fullmatch(repo),
          'Invalid target/repo')
    check(row.get('stage')=='AT_SOURCE' and row.get('category') in
          ('ACTIVE_AOSP_REVIEW','LOCAL_REMOTE_REVIEW'),'Not public core source')
    check(row.get('visibility')=='PUBLIC' and row.get('archived') is False and row.get('fork') is False,
          'Private, fork or archived repos are blocked')
    branch=row.get('branch');sha=row.get('head_sha')
    check(isinstance(branch,str) and len(branch)>0 and '..' not in branch and '/' not in branch[:1] and
          re.fullmatch(r'[A-Za-z0-9_./-]{1,200}',branch), 'Invalid default branch')
    check(isinstance(sha,str) and SHA.fullmatch(sha),'Verified source HEAD required')
    gh_access(target)
    src=json_api('repos/Deadknight/'+repo)
    check(src.get('full_name','').casefold()==('Deadknight/'+repo).casefold(),
          'GitHub source repository moved/redirected; stop, do not retry')
    check(src.get('permissions',{}).get('admin') is True, 'Source admin permission not verified')
    rid=src.get('id');check(isinstance(rid,int) and rid>0,'Invalid GitHub repository ID')
    check(src.get('private') is False and src.get('fork') is False and
          src.get('archived') is False and src.get('default_branch')==branch,
          'GitHub source metadata changed')
    check(branch_sha('Deadknight',repo,branch)==sha,'Source branch SHA drift')
    check(json_api('repos/'+target+'/'+repo,missing_ok=True) is None,
          'Target exists or cannot establish empty target')
    remotes=remote_changes(root,target,row)
    return {'status':'READY','repo':repo,'source_id':rid,'head':sha,'branch':branch,
            'remote_count':len(remotes),'active_manifest_ref_count':len(row.get('active_manifest_refs',[])),
            'remote_updates':remotes}

def do_transfer(payload):
    row=payload['row'];target=payload['target'];repo=row['name'];root=Path(payload['root'])
    before=preflight(payload)
    if payload.get('expected_id') is not None:
        check(before['source_id']==payload['expected_id'], 'Repository ID drift vs plan')
    p=proc(['gh','api','-X','POST','repos/Deadknight/'+repo+'/transfer',
            '-f','new_owner='+target],timeout=110)
    if p.returncode:
        return {'status':'TRANSFER_OUTCOME_UNKNOWN_DO_NOT_RETRY','repo':repo,
                'source_id':before['source_id'],'transfer_requested':True}
    dest=None
    for i in range(9):
        if i:time.sleep(2)
        try:dest=json_api('repos/'+target+'/'+repo,missing_ok=True)
        except Stop:continue
        if dest is not None:break
    if dest is None:
        return {'status':'TRANSFER_PENDING_VERIFY_MANUALLY','repo':repo,
                'source_id':before['source_id'],'transfer_requested':True}
    check(dest.get('id')==before['source_id'] and
          dest.get('full_name','').casefold()==(target+'/'+repo).casefold(),
          'GitHub transfer occurred but destination repo ID/name differs')
    check(dest.get('private') is False and dest.get('default_branch')==before['branch'] and
          branch_sha(target,repo,before['branch'])==before['head'],
          'GitHub transfer occurred but visibility, branch or SHA differs')
    changed=[]
    try:
        # All modifications are strictly local Git config, never AOSP XML or source files.
        for r in before['remote_updates']:
            fp=root/r['file']
            check(read_git_value(fp,r['key'])==r['old'],'Remote drift after GitHub transfer')
            q=proc(['git','config','--file',str(fp),'--replace-all',r['key'],r['new']],timeout=12)
            check(q.returncode==0,'Local Git remote rewrite failed')
            changed.append(r)
            check(read_git_value(fp,r['key'])==r['new'],'Remote readback failed')
        # Recheck GitHub after remotes have been rewritten.
        again=json_api('repos/'+target+'/'+repo)
        check(again.get('id')==before['source_id'] and
              branch_sha(target,repo,before['branch'])==before['head'], 'Final GitHub SHA mismatch')
    except Exception:
        errors=[]
        for r in reversed(changed):
            fp=root/r['file'];q=proc(['git','config','--file',str(fp),'--replace-all',r['key'],r['old']],timeout=12)
            if q.returncode or read_git_value(fp,r['key'])!=r['old']:errors.append(r['file']+' '+r['key'])
        if errors:raise Stop('LOCAL ROLLBACK INCOMPLETE: '+','.join(errors))
        raise Stop('GitHub TRANSFERRED, local remote change failed/rolled back; manual migration needed')
    return {'status':'COMPLETE','repo':repo,'repo_id':before['source_id'],
            'branch':before['branch'],'head':before['head'],
            'remotes_updated':len(changed),'active_xml_unchanged':True,
            'transfer_requested':True}

def main(payload):
    op=payload.get('operation')
    if op=='preflight':return preflight(payload)
    if op=='transfer':return do_transfer(payload)
    raise Stop('Unknown operation')

if __name__=='__main__':
    try:
        data=json.loads(sys.stdin.read())
        print(json.dumps(main(data),sort_keys=True))
    except Exception as exc:
        # Deliberately do not include GitHub auth tokens, raw remote URLs, or private files.
        print(json.dumps({'status':'STOP','error':str(exc)[:380]},sort_keys=True))
        sys.exit(3)
