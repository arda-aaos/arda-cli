#!/usr/bin/env python3
"""Self-contained Ubuntu final GitHub infrastructure transfer worker.

No AOSP source/manifest edits, repo sync, build, push, or device operation.
Does not modify AOSP manifest files or any Git config; infrastructure has zero mapped remotes.
"""
from __future__ import annotations
import hashlib, json, re, subprocess, sys, time, urllib.parse
from pathlib import Path

SHA = re.compile(r'^[a-f0-9]{40}$')
NAME = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,90}$')
KEY = re.compile(r'^remote\.[a-zA-Z0-9_.-]+\.url$')
BRANCH = re.compile(r'^[a-zA-Z0-9_./-]{1,200}$')
INFRA = ('arda-releases', 'arda-aaos-manifest')
PRIVATE = ('android_packages_apps_Car_MediaPrebuilt', 'android_packages_modules_Connectivity', 'arda-aaos-proprietary')
PRIVATE_IDS = {'android_packages_apps_Car_MediaPrebuilt':1332968855, 'android_packages_modules_Connectivity':1380230636, 'arda-aaos-proprietary':1291399037}
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

def private_access_snapshot(target):
    """Current GitHub access metadata, not a before/after transfer comparison.

    Do not expose collaborator usernames, team names, tokens or private sources
    in ZIP reports. Reject API/pagination uncertainty rather than passing it.
    """
    results=[]
    for name in PRIVATE:
        doc=api('repos/'+target+'/'+name)
        need(doc.get('id')==PRIVATE_IDS[name] and
             doc.get('full_name','').casefold()==(target+'/'+name).casefold() and
             doc.get('private') is True and doc.get('permissions',{}).get('admin') is True,
             'Private repo identity/visibility/admin access unverified: '+name)
        collabs=api('repos/'+target+'/'+name+'/collaborators?affiliation=all&per_page=100', allow_list=True)
        teams=api('repos/'+target+'/'+name+'/teams?per_page=100', allow_list=True)
        need(len(collabs)<100 and len(teams)<100, 'Private access list may be paginated; manual audit: '+name)
        need(all(isinstance(x,dict) and isinstance(x.get('login'),str) for x in collabs),
             'Invalid collaborator list: '+name)
        need(all(isinstance(x,dict) and isinstance(x.get('slug'),str) for x in teams),
             'Invalid team list: '+name)
        roles={}
        for x in collabs:
            role=x.get('role_name') or 'unknown'
            need(isinstance(role,str) and len(role)<80,'Invalid collaborator role')
            roles[role]=roles.get(role,0)+1
        results.append({'repo':name,'id':doc['id'],'visibility':'PRIVATE',
                        'collaborator_count':len(collabs),'team_count':len(teams),
                        'collaborator_role_counts':roles,'status':'CURRENT_ACCESS_OBSERVED_NOT_HISTORICALLY_COMPARED'})
    return results

def xml_snapshot(root):
    """Freeze active/local/manifests XML bytes, without editing any content."""
    all_files=[]
    for folder in (root/'.repo/local_manifests',root/'.repo/manifests'):
        if folder.is_dir(): all_files += list(folder.glob('*.xml'))
    if (root/'.repo/manifest.xml').exists():all_files.append(root/'.repo/manifest.xml')
    files=[]
    for fp in sorted(set(all_files)):
        need(fp.is_file() and fp.resolve().is_relative_to(root.resolve()),'XML outside AOSP root')
        b=fp.read_bytes()
        files.append({'file':fp.relative_to(root).as_posix(),
                      'sha256':hashlib.sha256(b).hexdigest(),
                      'old_owner_url_mentions':b.count(b'github.com/Deadknight/')})
    need(files,'No AOSP manifest XML found; cannot freeze manifest baseline')
    digest=hashlib.sha256(json.dumps(files,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    return {'digest':digest,'files':len(files),
            'old_owner_url_mentions':sum(x['old_owner_url_mentions'] for x in files)}

def constraints(row,phase):
    repo=row.get('name')
    need(phase=='infra' and repo in INFRA and NAME.fullmatch(repo or '') is not None,
         'Infra whitelist or name mismatch')
    need(row.get('stage')=='AT_SOURCE' and row.get('category')=='INFRA_LAST' and
         row.get('archived') is False and row.get('fork') is False and
         row.get('visibility')=='PUBLIC','Infrastructure source classification changed')
    need(row.get('branch')=='main' and
         (row.get('head_sha') is None or (isinstance(row.get('head_sha'),str) and
          SHA.fullmatch(row['head_sha']))),'Infrastructure main/HEAD record invalid')
    need(row.get('git_remotes')==[] and row.get('active_manifest_refs')==[] and
         row.get('library_manifest_refs')==[],
         'Unexpected manifest or Ubuntu remote dependency for infrastructure')


def preflight(payload):
    row=payload['row'];phase=payload['phase'];root=Path(payload['root']);target=payload['target'];repo=row['name']
    need(root.is_absolute() and root.is_dir() and (root/'.repo').is_dir(),'AOSP root missing')
    need(target=='arda-aaos','Unsupported organization target')
    constraints(row,phase)
    gh_access(target)
    data=details('Deadknight',repo,row)
    need(api('repos/'+target+'/'+repo,missing_ok=True) is None,
         'Destination already has repo or redirect; do not repeat')
    need(expected_changes(root,target,row)==[],'Unexpected infrastructure Git remotes')
    access=private_access_snapshot(target)
    manifest=xml_snapshot(root)
    return {'status':'READY','repo':repo,'source_id':data['id'],'head':data['head'],
            'branch':data['branch'],'visibility':'PUBLIC','remote_count':0,
            'active_xml_count':0,'updates':[],'private_access':access,'manifest':manifest,
            'dependency_notice':'Existing release clients/CI and historical manifest URLs require later owner-aware audit'}

def transfer(payload):
    row=payload['row'];name=row['name'];target=payload['target'];root=Path(payload['root'])
    before=preflight(payload)
    need(payload.get('expected_id')==before['source_id'] and
         payload.get('expected_head')==before['head'] and
         payload.get('expected_access')==before['private_access'] and
         payload.get('expected_manifest')==before['manifest'],
         'Repo, access or manifest drift from frozen plan')
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
        need(private_access_snapshot(target)==before['private_access'],
             'Private access metadata changed during infrastructure migration')
        need(xml_snapshot(root)==before['manifest'],
             'AOSP XML manifest bytes changed during infrastructure migration')
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
            'active_xml_unchanged':True, 'private_access_unchanged':True,
            'manifest_digest':before['manifest']['digest']}

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
