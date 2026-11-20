#!/usr/bin/env python3
"""Ubuntu-side read-only GitHub organization migration inventory.

Absolutely no repository creation/transfer, git fetch, manifest writes or repo sync.
Only metadata from gh and local AOSP manifests/Git configuration is returned.
"""
from __future__ import annotations
import json, re, subprocess, sys, urllib.parse, xml.etree.ElementTree as ET
from pathlib import Path

ORG_RE = re.compile(r'^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$')
GIT_RE = re.compile(r'^(?:https://github\.com/|git@github\.com:|ssh://git@github\.com/)(Deadknight|arda-aaos)/([A-Za-z0-9_.-]+?)(?:\.git)?/?$', re.I)
PROJECT_TAGS={'project','extend-project','remove-project'}
INFRA={'arda-aaos-manifest','arda-releases'}

class Stop(Exception): pass

def require(cond, msg):
    if not cond:raise Stop(msg)

def gh(*args,timeout=125):
    try:
        p=subprocess.run(['gh',*args],stdin=subprocess.DEVNULL,capture_output=True,text=True,
            timeout=timeout,errors='replace')
    except (OSError,subprocess.TimeoutExpired):raise Stop('gh unavailable or timed out; no mutations') from None
    require(p.returncode==0,'GitHub authorization/API unavailable; no inventory generated')
    return p.stdout

def repo_rows(raw):
    try:data=json.loads(raw)
    except (ValueError,TypeError):raise Stop('Malformed GitHub inventory JSON') from None
    require(isinstance(data,list),'Invalid GitHub repository list')
    ret={}
    for row in data:
        if not isinstance(row,dict):continue
        name=row.get('name')
        if not isinstance(name,str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,100}',name):continue
        if not (name.startswith(('android_','arda-','arda_')) or name in ('ArdaPlatform','ARDA-CLI')):continue
        ref=row.get('defaultBranchRef') or {}
        head=ref.get('target') or {}
        sha=head.get('oid','') if isinstance(head,dict) else ''
        if not isinstance(sha,str) or not re.fullmatch(r'[0-9a-f]{40}',sha):sha=None
        ret[name.casefold()]={'name':name,'visibility':str(row.get('visibility','UNKNOWN')).upper(),
             'archived':bool(row.get('isArchived',False)),'fork':row.get('isFork'),
             'branch':ref.get('name') if isinstance(ref,dict) else None,'head_sha':sha}
    return ret

def project_references(root,candidates):
    """Find exact XML project names; flag active/local and repository manifests separately."""
    repo=root/'.repo'; refs={k:[] for k in candidates}
    paths=[]
    for label,folder in (('local',repo/'local_manifests'),('manifest_library',repo/'manifests')):
        if folder.is_dir():
            for fp in folder.glob('*.xml'):paths.append((label,fp))
    p=repo/'manifest.xml'
    if p.exists():paths.append(('main',p))
    for label,fp in paths:
        require(fp.resolve().is_relative_to(root.resolve()),'Unexpected manifest symlink outside root')
        try:tree=ET.parse(fp)
        except (ET.ParseError,OSError,UnicodeError):
            # Cannot safely assert the project is not referenced.
            raise Stop('Cannot parse AOSP manifest XML: '+fp.name) from None
        for element in tree.iter():
            if element.tag not in PROJECT_TAGS:continue
            project=element.get('name','')
            if not isinstance(project,str):continue
            key=project.split('/')[-1].casefold()
            if key not in refs:continue
            ref={'file':fp.relative_to(root).as_posix(),'scope':label,
                 'project':project,'path':element.get('path','')}
            if ref not in refs[key]:refs[key].append(ref)
    return refs

def exact_remote(url):
    m=GIT_RE.fullmatch(url)
    if not m:return None
    return m.group(1).casefold(),m.group(2).casefold()

def local_git_remote_refs(root,candidates):
    """Read Git config with git itself, never emit raw credential-bearing URLs."""
    results={k:[] for k in candidates}
    project_dir=root/'.repo/projects'
    if not project_dir.is_dir():return results
    files=sorted(project_dir.rglob('config'))
    for fp in files:
        require(fp.is_file() and not fp.is_symlink() and fp.resolve().is_relative_to(root.resolve()),
                'Unsafe AOSP Git config path')
        try:
            p=subprocess.run(['git','config','--file',str(fp),'--null','--get-regexp',r'^remote\..*\.url$'],
                             capture_output=True,timeout=12)
        except (OSError,subprocess.TimeoutExpired):raise Stop('Unable to inspect Git remote configs') from None
        if p.returncode==1 and not p.stdout:continue
        require(p.returncode==0,'Git remote config read failed')
        for item in p.stdout.split(b'\0'):
            if not item:continue
            require(b'\n' in item,'Malformed remote entry')
            raw_key,raw_url=item.split(b'\n',1)
            key=raw_key.decode('utf8','replace')
            url=raw_url.decode('utf8','replace')
            matched=exact_remote(url)
            if matched is None:continue
            owner,name=matched
            if name not in results:continue
            rec={'file':fp.relative_to(root).as_posix(),'remote':key,
                 'owner':'SOURCE' if owner=='deadknight' else 'TARGET'}
            if rec not in results[name]:results[name].append(rec)
    return results

def classify(row,local_refs,remote_refs,conflict):
    name=row['name']
    active=[x for x in local_refs if x['scope'] in ('local','main')]
    if conflict:return 'NAME_CONFLICT_HOLD'
    if row['archived']:return 'ARCHIVED_HOLD'
    if row['visibility']!='PUBLIC':return 'PRIVATE_REVIEW'
    if name in INFRA:return 'INFRA_LAST'
    if active:return 'ACTIVE_AOSP_REVIEW'
    if remote_refs:return 'LOCAL_REMOTE_REVIEW'
    if local_refs:return 'MANIFEST_LIBRARY_REVIEW'
    return 'INDEPENDENT_REVIEW'

def resolve_default_branch_sha(owner, row):
    """`gh repo list --json defaultBranchRef` supplies the NAME, not target.oid.

    A second read-only GitHub REST call is required to obtain a trustworthy
    default-branch commit SHA. Never infer it from local git HEAD or fabricate
    a value. The later pilot independently verifies repo ID, branch and SHA.
    """
    name=row.get('name')
    branch=row.get('branch')
    require(isinstance(owner,str) and owner=='Deadknight','Unexpected source owner')
    require(isinstance(name,str) and re.fullmatch(r'[A-Za-z0-9_.-]{1,100}',name)
            and '..' not in name,'Invalid GitHub repository name for SHA lookup')
    require(isinstance(branch,str) and bool(branch) and len(branch)<=200 and
            re.fullmatch(r'[A-Za-z0-9_./-]+',branch) and '..' not in branch and
            not branch.startswith('/') and not branch.endswith('/'),
            'Invalid/default GitHub branch for '+name+'; no transfer')
    endpoint='repos/'+owner+'/'+name+'/commits/'+urllib.parse.quote(branch,safe='')
    sha=gh('api',endpoint,'--jq','.sha').strip()
    require(re.fullmatch(r'[a-f0-9]{40}',sha) is not None,
            'GitHub default-branch HEAD SHA lookup invalid for '+name+'; no transfer')
    return sha


def inventory(payload):
    target=payload.get('target')
    root=Path(payload.get('root',''))
    require(isinstance(target,str) and ORG_RE.fullmatch(target) and target.casefold()!='deadknight',
            'Invalid target organization')
    require(root.is_absolute() and root.is_dir() and (root/'.repo').is_dir() and '..' not in root.parts,
            'Existing AOSP source root required')
    actor=gh('api','user','--jq','.login').strip()
    require(actor.casefold()=='deadknight','Expected Deadknight Ubuntu gh actor')
    # query role/state separately using JSON rather than brittle jq representation
    try:
        m=json.loads(gh('api',f'user/memberships/orgs/{target}'))
    except ValueError:raise Stop('Invalid organization membership response') from None
    require(m.get('role')=='admin' and m.get('state')=='active','Organization admin/active membership required')
    fields='name,visibility,isArchived,isFork,defaultBranchRef'
    before=repo_rows(gh('repo','list','Deadknight','--limit','1000','--json',fields,timeout=150))
    after=repo_rows(gh('repo','list',target,'--limit','1000','--json',fields,timeout=150))
    candidates={**before,**after}
    refs=project_references(root,candidates)
    remotes=local_git_remote_refs(root,candidates)
    rows=[]
    for key in sorted(candidates):
        source=before.get(key);dest=after.get(key)
        b=source or dest
        conflict=(source is not None and dest is not None)
        refs_here=refs.get(key,[]);remotes_here=remotes.get(key,[])
        if dest and not source:stage='TRANSFERRED'
        elif conflict:stage='BOTH_OWNERS_HOLD'
        else:stage='AT_SOURCE'
        category='TRANSFERRED' if stage=='TRANSFERRED' else classify(b,refs_here,remotes_here,conflict)
        # Only public, non-fork, non-manifest remote-linked source candidates need
        # SHA enrichment for the guarded wave. Do not query private/critical repos
        # or treat an unverified value as a transferable candidate.
        if (stage=='AT_SOURCE' and (category=='LOCAL_REMOTE_REVIEW' or
                (category=='ACTIVE_AOSP_REVIEW' and payload.get('enrich_active_sha') is True))
                and b.get('visibility')=='PUBLIC' and b.get('archived') is False
                and b.get('fork') is False and isinstance(b.get('branch'),str) and bool(b.get('branch'))
                and all(rec.get('owner')=='SOURCE' for rec in remotes_here)):
            b={**b, 'head_sha': resolve_default_branch_sha('Deadknight', b)}
        rows.append({**b,'stage':stage,'category':category,
             'active_manifest_refs':[r for r in refs_here if r['scope'] in ('local','main')],
             'library_manifest_refs':[r for r in refs_here if r['scope']=='manifest_library'],
             'git_remotes':remotes_here})
    counts={}
    for row in rows:counts[row['category']]=counts.get(row['category'],0)+1
    return {'status':'READ_ONLY_INVENTORY','target':target,'actor':actor,
       'organization_membership':'admin:active','source_remaining':len(before),
       'target_present':len(after),'total_distinct':len(rows),
       'categories':counts,'repositories':rows,
       'automatic_transfer':False,'automatic_manifest_mutation':False,'automatic_origin_mutation':False,
       'notes':['Project references reflect XML entries; missing entries do not prove lack of runtime/CI dependency.',
                'Manifests inside .repo/manifests are catalogued separately from active/local XML.',
                'Read-only inventory is not authorization to transfer any repository.']}

def main():
    payload=json.loads(sys.stdin.read())
    return inventory(payload)

if __name__=='__main__':
    try:print(json.dumps(main(),sort_keys=True,ensure_ascii=False))
    except Exception as exc:
        print(json.dumps({'status':'STOP','error':str(exc)[:250]},sort_keys=True))
        sys.exit(3)
