#!/usr/bin/env python3
"""Ubuntu-side no-write audit of GitHub transfers and retained AOSP manifest URLs.

Reads only metadata. Never prints Git auth credentials, arbitrary URL values, or private
repository files. All GitHub endpoints are requested explicitly using `gh api`.
"""
from __future__ import annotations
import json, re, subprocess, sys, urllib.parse, xml.etree.ElementTree as ET
from pathlib import Path

NAME=re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,90}$')
SHA=re.compile(r'^[0-9a-f]{40}$')
ORG=re.compile(r'^[A-Za-z0-9-]{1,39}$')
class AuditStop(Exception):pass

def require(ok, msg):
    if not ok:raise AuditStop(msg)

def api(endpoint, *, list_response=False):
    try:
        p=subprocess.run(['gh','api',endpoint],text=True,capture_output=True,stdin=subprocess.DEVNULL,timeout=35)
    except (OSError,subprocess.TimeoutExpired):raise AuditStop('GitHub metadata unavailable') from None
    require(p.returncode==0,'GitHub API metadata request failed')
    try:data=json.loads(p.stdout)
    except (TypeError,ValueError):raise AuditStop('GitHub API metadata invalid') from None
    require(isinstance(data,list if list_response else dict),'GitHub metadata type mismatch')
    return data

def verify_repo(owner, r):
    name=r['name']; stage=r['stage']; branch=r.get('branch')
    require(NAME.fullmatch(name) is not None,'Unsafe repo name')
    require(stage in ('TRANSFERRED','AT_SOURCE'),'Unexpected repo stage')
    # gh repo list defaultBranchRef is absent for a repository with no branches.
    # The inventory serializes that as '' or None; neither is a branch name.
    # A genuinely unsafe NON-EMPTY branch name must still be rejected.
    if branch in (None, ''):
        require(branch is None or isinstance(branch,str),'Unsafe default branch')
        require(r.get('head_sha') is None,'Branchless inventory has unexpected HEAD SHA: '+name)
        branch=None
    else:
        require(isinstance(branch,str) and
                re.fullmatch(r'[A-Za-z0-9_./-]{1,200}',branch) is not None and
                '..' not in branch and not branch.startswith('/') and
                not branch.endswith('/'), 'Unsafe default branch')
    doc=api('repos/'+owner+'/'+name)
    require(doc.get('full_name','').casefold()==(owner+'/'+name).casefold(), 'Repo redirects or owner mismatch: '+name)
    rid=doc.get('id')
    require(isinstance(rid,int) and rid>0,'Invalid GitHub repository ID: '+name)
    if branch is None:
        # REST may expose a nominal `default_branch: "main"` even though no
        # Git ref exists. Require an explicit 200 + [] from the authenticated
        # branches endpoint before treating the repository as branchless.
        branches=api('repos/'+owner+'/'+name+'/branches?per_page=1',list_response=True)
        require(not branches,'Inventory has no default branch but GitHub has branches: '+name)
        nominal=doc.get('default_branch')
        require(nominal in (None, '') or (isinstance(nominal,str) and
                re.fullmatch(r'[A-Za-z0-9_./-]{1,200}',nominal) is not None and
                '..' not in nominal and not nominal.startswith('/') and
                not nominal.endswith('/')), 'Unsafe nominal default branch: '+name)
    else:
        require(doc.get('default_branch')==branch,'Default branch drift: '+name)
    private=doc.get('private')
    require(isinstance(private,bool), 'Visibility unavailable: '+name)
    expected_visibility='PRIVATE' if private else 'PUBLIC'
    require(r.get('visibility')==expected_visibility,'Visibility drift: '+name)
    require(doc.get('archived')==r.get('archived'),'Archive flag drift: '+name)
    default_sha=None
    if branch:
        commit=api('repos/'+owner+'/'+name+'/commits/'+urllib.parse.quote(branch,safe=''))
        default_sha=commit.get('sha')
        require(isinstance(default_sha,str) and SHA.fullmatch(default_sha),'Bad branch SHA: '+name)
        expected=r.get('head_sha')
        if expected is not None:require(expected==default_sha,'Inventory HEAD SHA mismatch: '+name)
    return {'name':name,'repo':name,'owner':owner,'stage':stage,'repository_id':rid,
            'default_branch':branch,'head_sha':default_sha,
            'branch_state':'NO_BRANCHES_VERIFIED' if branch is None else 'BRANCH_SHA_VERIFIED',
            'visibility':expected_visibility,
            'category':r.get('category'), 'active_xml_count':len(r.get('active_manifest_refs',[])),
            'git_remote_count':len(r.get('git_remotes',[])),
            'stale_source_remotes':sum(x.get('owner')=='SOURCE' for x in r.get('git_remotes',[])),
            'target_remotes':sum(x.get('owner')=='TARGET' for x in r.get('git_remotes',[]))}

def manifest_legacy(root):
    repo=root/'.repo';paths=[]
    for folder in (repo/'local_manifests',repo/'manifests'):
        if folder.is_dir():paths+=sorted(folder.rglob('*.xml'))
    if (repo/'manifest.xml').is_file():paths.append(repo/'manifest.xml')
    summary=[]
    for fp in sorted(set(paths)):
        require(fp.is_file() and fp.resolve().is_relative_to(root.resolve()),'Manifest path unsafe')
        try:tree=ET.parse(fp)
        except (ET.ParseError,OSError):raise AuditStop('Manifest parse error: '+fp.name) from None
        legacy=0;target=0;total=0
        for element in tree.iter():
            if element.tag not in ('remote','project','extend-project','remove-project','include','submanifest'):continue
            for value in element.attrib.values():
                if not isinstance(value,str):continue
                total+=1
                if re.search(r'github\.com[/:]Deadknight(?:/|$)',value,re.I):legacy+=1
                if re.search(r'github\.com[/:]arda-aaos(?:/|$)',value,re.I):target+=1
        if legacy or target:
            summary.append({'file':fp.relative_to(root).as_posix(),
                            'old_owner_url_attributes':legacy,'new_owner_url_attributes':target})
    return summary

def main(payload):
    root=Path(payload['root']);target=payload['target'];rows=payload['repositories']
    require(root.is_absolute() and root.is_dir() and (root/'.repo').is_dir(),'AOSP root required')
    require(isinstance(target,str) and ORG.fullmatch(target) and target=='arda-aaos','Target must be arda-aaos')
    require(isinstance(rows,list) and 1<=len(rows)<=100 and len({x.get('name') for x in rows})==len(rows), 'Repo set invalid')
    actor=api('user');require(actor.get('login','').casefold()=='deadknight','Unexpected GitHub actor')
    membership=api('user/memberships/orgs/'+target)
    require(membership.get('role')=='admin' and membership.get('state')=='active','Org admin required')
    verified=[]
    for row in rows:
        stage=row.get('stage')
        require(stage in ('TRANSFERRED','AT_SOURCE'),'Conflicting repo ownership; STOP')
        owner=target if stage=='TRANSFERRED' else 'Deadknight'
        verified.append(verify_repo(owner,row))
    return {'status':'RECONCILE_READ_ONLY_PASS','repositories':verified,
            'manifest_owner_urls':manifest_legacy(root),
            'github_verified_count':len(verified),
            'transferred_verified':sum(x['stage']=='TRANSFERRED' for x in verified),
            'remaining_verified':sum(x['stage']=='AT_SOURCE' for x in verified),
            'no_writes':True}

if __name__=='__main__':
    try:
        payload=json.loads(sys.stdin.read())
        print(json.dumps(main(payload),sort_keys=True))
    except Exception as exc:
        print(json.dumps({'status':'STOP','error':str(exc)[:220]},sort_keys=True))
        sys.exit(3)
