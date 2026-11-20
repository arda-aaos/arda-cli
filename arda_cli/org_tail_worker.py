#!/usr/bin/env python3
"""Self-contained Ubuntu guarded special/public-private GitHub transfer worker.

No AOSP source/manifest edits, repo sync, build, push, or device operation.
Updates only an explicitly frozen, exact-matching Git config URL after transfer.
"""
from __future__ import annotations
import json, re, subprocess, sys, time, urllib.parse
from pathlib import Path

SHA = re.compile(r'^[a-f0-9]{40}$')
NAME = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,90}$')
KEY = re.compile(r'^remote\.[a-zA-Z0-9_.-]+\.url$')
BRANCH = re.compile(r'^[a-zA-Z0-9_./-]{1,200}$')
SPECIAL = ('ArdaPlatform', 'arda-aaos-vendor', 'android_external_libudev-zero')
PRIVATE = ('android_packages_apps_Car_MediaPrebuilt', 'android_packages_modules_Connectivity', 'arda-aaos-proprietary')
class Stop(Exception):pass

def need(expr, msg):
    if not expr: raise Stop(msg)

def proc(cmd,timeout=45):
    try:
        return subprocess.run(cmd,stdin=subprocess.DEVNULL,capture_output=True,text=True,
                              errors='replace',timeout=timeout)
    except (OSError,subprocess.TimeoutExpired):
        raise Stop('GitHub/Git command unavailable/timeout; transfer outcome may be uncertain') from None

def api(endpoint, missing_ok=False, allow_list=False):
    p=proc(['gh','api',endpoint],timeout=55)
    if p.returncode:
        http=re.search(r'\bHTTP[ /]+(\d{3})\b',p.stderr,re.I)
        if missing_ok and http and http.group(1)=='404':return None
        raise Stop('GitHub API unverified failure on '+endpoint)
    try:doc=json.loads(p.stdout)
    except ValueError:raise Stop('Invalid GitHub API data') from None
    need(isinstance(doc,list if allow_list else dict),'Unexpected GitHub API record')
    return doc

def validated_branch(row):
    branch=row.get('branch')
    if branch in ('',None):
        need(row.get('head_sha') is None, 'Uncommitted source has unexpected inventory SHA')
        return None
    need(isinstance(branch,str) and BRANCH.fullmatch(branch) and '..' not in branch
         and not branch.startswith('/') and not branch.endswith('/'),'Unsafe branch')
    return branch

def sha_for(owner, name, branch):
    data=api('repos/'+owner+'/'+name+'/commits/'+urllib.parse.quote(branch,safe=''))
    sha=data.get('sha')
    need(isinstance(sha,str) and SHA.fullmatch(sha), 'Branch commit SHA missing')
    return sha

def details(owner,name,row, expected_id=None, expected_sha=None):
    doc=api('repos/'+owner+'/'+name)
    need(doc.get('full_name','').casefold()==(owner+'/'+name).casefold(),'GitHub redirect/owner mismatch')
    rid=doc.get('id')
    need(isinstance(rid,int) and rid>0,'Invalid GitHub repo ID')
    if expected_id is not None:need(rid==expected_id,'Repository ID differs from frozen plan')
    private=(row['visibility']=='PRIVATE')
    need(doc.get('private') is private and doc.get('fork') is row['fork'] and
         doc.get('archived') is False,'GitHub repository metadata/visibility mismatch')
    need(doc.get('permissions',{}).get('admin') is True,'Admin permission not verified')
    branch=validated_branch(row)
    if branch is None:
        branches=api('repos/'+owner+'/'+name+'/branches?per_page=1',allow_list=True)
        need(not branches,'Expected branchless repository but branches exist')
        nominal=doc.get('default_branch')
        need(nominal in (None,'') or (isinstance(nominal,str) and BRANCH.fullmatch(nominal)
             and '..' not in nominal and not nominal.startswith('/') and not nominal.endswith('/')),
             'Unsafe nominal default branch')
        sha=None
    else:
        need(doc.get('default_branch')==branch,'GitHub default branch differs')
        sha=sha_for(owner,name,branch)
        prior=row.get('head_sha')
        if prior is not None:need(prior==sha,'Inventory SHA differs')
    if expected_sha is not None:need(sha==expected_sha,'GitHub branch SHA drift from frozen plan')
    return {'id':rid,'head':sha,'branch':branch,'visibility':row['visibility']}

def gh_access(target):
    user=api('user');member=api('user/memberships/orgs/'+target)
    need(str(user.get('login','')).casefold()=='deadknight','Expected gh actor Deadknight')
    need(member.get('state')=='active' and member.get('role')=='admin','Org admin/active required')

def read_config(fp,key):
    p=proc(['git','config','--file',str(fp),'--get',key],timeout=12)
    need(p.returncode in (0,1),'Git config read failure')
    return p.stdout.strip() if p.returncode==0 else None

def expected_changes(root,target,row):
    ret=[];repo=row['name'];remotes=row.get('git_remotes')
    need(isinstance(remotes,list),'Remote inventory missing')
    for r in remotes:
        need(isinstance(r,dict) and r.get('owner')=='SOURCE','Unexpected Git remote ownership')
        rel=r.get('file');key=r.get('remote')
        need(isinstance(rel,str) and rel.startswith('.repo/projects/') and rel.endswith('/config')
             and '..' not in Path(rel).parts and isinstance(key,str) and KEY.fullmatch(key),
             'Unsafe Git config path or key')
        fp=root/rel
        need(fp.is_file() and not fp.is_symlink() and fp.resolve().is_relative_to(root.resolve()),
             'Git config must be a regular file beneath AOSP root')
        current=read_config(fp,key)
        change=None
        for prefix,suffix in (('https://github.com/',''),('git@github.com:',''),('ssh://git@github.com/','')):
            for ending in ('','.git'):
                old=prefix+'Deadknight/'+repo+ending
                if current==old:
                    change={'file':rel,'key':key,'old':old,'new':prefix+target+'/'+repo+ending}
        need(change is not None,'Git remote is not an exact source URL: '+repo+' '+rel+' '+key)
        ret.append(change)
    need(len({(x['file'],x['key']) for x in ret})==len(ret),'Duplicate remote record')
    return ret

def constraints(row,phase):
    repo=row.get('name')
    need(NAME.fullmatch(repo or '') is not None,'Unsafe GitHub repo name')
    need(row.get('stage')=='AT_SOURCE' and row.get('archived') is False
         and row.get('fork') is False,'Only active source non-fork repos supported')
    if phase=='public-special':
        need(repo in SPECIAL and row.get('visibility')=='PUBLIC','Public special group whitelist mismatch')
        need(row.get('category') in ('INDEPENDENT_REVIEW','ACTIVE_AOSP_REVIEW'),
             'Unexpected special repo category')
    elif phase=='private':
        need(repo in PRIVATE and row.get('visibility')=='PRIVATE'
             and row.get('category')=='PRIVATE_REVIEW','Private repo classification mismatch')
    else:raise Stop('Unknown phase')
    # Review invariants come from the audited 22-repository inventory. Any
    # source layout change requires a fresh explicit investigation, not guessing.
    expected = {
        'ArdaPlatform': (0, 0, False),
        'arda-aaos-vendor': (0, 0, False),
        'android_external_libudev-zero': (1, 1, True),
        'android_packages_apps_Car_MediaPrebuilt': (1, 0, False),
        'android_packages_modules_Connectivity': (1, 0, True),
        'arda-aaos-proprietary': (0, 1, False),
    }
    remotes_count, refs_count, branchless = expected[repo]
    need(isinstance(row.get('git_remotes'),list) and
         len(row['git_remotes'])==remotes_count,'Audited Git remote count changed')
    need(isinstance(row.get('active_manifest_refs'),list) and
         isinstance(row.get('library_manifest_refs'),list) and
         not row['library_manifest_refs'] and
         len(row['active_manifest_refs'])==refs_count,'Audited AOSP manifest references changed')
    need((row.get('branch') in (None,'')) is branchless,'Audited branch state changed')
    refs=row['active_manifest_refs']
    if repo=='android_external_libudev-zero':
        need(all(x.get('project')=='raspberry-vanilla/android_external_libudev-zero' and
            x.get('scope') in ('local','main') for x in refs),
            'libudev-zero active project owner changed')
    elif repo=='arda-aaos-proprietary':
        need(all(x.get('project')=='arda-aaos-proprietary' and
            x.get('scope') in ('local','main') for x in refs),
            'Proprietary manifest project changed')
    else:
        need(not refs,'Unexpected active manifest for independent/private repo')

def preflight(payload):
    row=payload['row'];phase=payload['phase'];root=Path(payload['root']);target=payload['target'];repo=row['name']
    need(root.is_absolute() and root.is_dir() and (root/'.repo').is_dir(),'AOSP root missing')
    need(target=='arda-aaos','Unsupported GitHub organization target')
    constraints(row,phase)
    gh_access(target)
    data=details('Deadknight',repo,row)
    need(api('repos/'+target+'/'+repo,missing_ok=True) is None,
         'Target already has repo (or GitHub redirect); do not repeat transfer')
    changes=expected_changes(root,target,row)
    return {'status':'READY','repo':repo,'source_id':data['id'],'head':data['head'],
            'branch':data['branch'],'visibility':row['visibility'],
            'remote_count':len(changes),'updates':changes,
            'active_xml_count':len(row['active_manifest_refs'])}

def transfer(payload):
    row=payload['row'];name=row['name'];target=payload['target'];root=Path(payload['root'])
    before=preflight(payload)
    need(payload.get('expected_id')==before['source_id'] and
         payload.get('expected_head')==before['head'],'Repository identity drift from plan')
    p=proc(['gh','api','-X','POST','repos/Deadknight/'+name+'/transfer',
            '-f','new_owner='+target],timeout=110)
    if p.returncode:
        return {'status':'TRANSFER_OUTCOME_UNKNOWN_DO_NOT_RETRY','repo':name,'request_sent':True}
    dest=None
    for i in range(9):
        if i:time.sleep(2)
        try:dest=details(target,name,row,expected_id=before['source_id'],expected_sha=before['head'])
        except Stop:continue
        if dest is not None:break
    if dest is None:
        return {'status':'TRANSFER_PENDING_VERIFY_MANUALLY','repo':name,'request_sent':True}
    changed=[]
    try:
        for update in before['updates']:
            fp=root/update['file'];need(read_config(fp,update['key'])==update['old'],'Remote drift after transfer')
            p=proc(['git','config','--file',str(fp),'--replace-all',update['key'],update['new']],timeout=15)
            need(p.returncode==0 and read_config(fp,update['key'])==update['new'],'Remote migration failed')
            changed.append(update)
        details(target,name,row,expected_id=before['source_id'],expected_sha=before['head'])
    except Exception:
        bad=[]
        for item in reversed(changed):
            fp=root/item['file']
            back=proc(['git','config','--file',str(fp),'--replace-all',item['key'],item['old']],timeout=15)
            if back.returncode or read_config(fp,item['key'])!=item['old']:
                bad.append(item['file']+' / '+item['key'])
        if bad:raise Stop('GITHUB_TRANSFERRED_LOCAL_ROLLBACK_INCOMPLETE: '+', '.join(bad))
        raise Stop('GITHUB_TRANSFERRED_LOCAL_REMOTE_ROLLED_BACK; manual audit needed')
    return {'status':'COMPLETE','repo':name,'repo_id':before['source_id'],
            'visibility':row['visibility'],'branch':before['branch'],
            'head':before['head'],'remotes_updated':len(changed),
            'active_xml_unchanged':True}

def main(payload):
    op=payload.get('operation')
    if op=='preflight':return preflight(payload)
    if op=='transfer':return transfer(payload)
    raise Stop('Unsupported operation')

if __name__=='__main__':
    try:
        data=json.loads(sys.stdin.read())
        print(json.dumps(main(data),sort_keys=True))
    except Exception as exc:
        print(json.dumps({'status':'STOP','error':str(exc)[:320]},sort_keys=True))
        sys.exit(3)
