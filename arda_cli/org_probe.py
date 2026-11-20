#!/usr/bin/env python3
"""Ephemeral Ubuntu GitHub organization migration PLAN. Absolutely read-only."""
from __future__ import annotations
import json, re, subprocess, sys
from pathlib import Path


def gh(*args,timeout=95):
    try:
        p=subprocess.run(['gh',*args],capture_output=True,timeout=timeout)
    except (OSError,subprocess.TimeoutExpired):return 125,b''
    return p.returncode,p.stdout


def inventory(raw):
    obj=json.loads(raw)
    if not isinstance(obj,list):raise ValueError('Invalid gh repository list')
    result=[]
    for row in obj:
        name=row.get('name','')
        if not isinstance(name,str):continue
        if not (name.startswith(('android_','arda-','arda_')) or name in ('ArdaPlatform','ARDA-CLI')):
            continue
        result.append({'name':name,'visibility':str(row.get('visibility','UNKNOWN')),
                       'archived':bool(row.get('isArchived',False))})
    return sorted(result,key=lambda x:x['name'].casefold())


def main():
    payload=json.loads(sys.stdin.read())
    target=payload.get('target','arda-aaos')
    if not isinstance(target,str) or not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?',target):
        raise ValueError('Invalid GitHub organization name')
    rc,who=gh('api','user','--jq','.login')
    if rc:raise ValueError('gh authentication unavailable')
    actor=who.decode('utf8','replace').strip()
    if actor.casefold()!='deadknight':raise ValueError('Expected Deadknight GitHub account not logged in')
    rc,raw=gh('repo','list','Deadknight','--limit','1000','--json','name,visibility,isArchived',timeout=140)
    if rc:raise ValueError('Unable to obtain source GitHub repository inventory')
    candidates=inventory(raw)
    rc,orgraw=gh('api','orgs/'+target,'--jq','.login')
    org_state='EXISTS' if rc==0 else 'NOT_PUBLIC_OR_INACCESSIBLE'
    conflicts=[];membership='UNKNOWN';existing=[]
    if org_state=='EXISTS':
        rc,rows=gh('repo','list',target,'--limit','1000','--json','name,visibility,isArchived',timeout=140)
        if rc==0:
            existing=inventory(rows)
            names={r['name'].casefold() for r in existing}
            conflicts=[r['name'] for r in candidates if r['name'].casefold() in names]
        else:
            org_state='EXISTS_REPO_LIST_INACCESSIBLE'
        mrc,mraw=gh('api','user/memberships/orgs/'+target,'--jq','.role')
        if mrc==0:membership=mraw.decode('utf8','replace').strip()
        else:membership='NO_VERIFIED_MEMBERSHIP'
    root=Path(payload.get('root',''))
    references=[]
    local=root/'.repo/local_manifests'
    if local.is_dir():
        for p in sorted(local.glob('*.xml')):
            try:
                body=p.read_text('utf8')
            except (OSError, UnicodeError):continue
            if 'github.com/Deadknight' in body or 'arda-github' in body:
                references.append(p.name)
    return {'target':target,'actor':actor,'organization_state':org_state,
            'membership':membership,'source_repositories':candidates,
            'candidate_count':len(candidates),'name_conflicts':conflicts,
            'local_manifest_files_referencing_source_owner':references,
            'read_only':True,'automatic_transfer':False,'automatic_url_rewrite':False,
            'warning':'404 or private organization does not prove name availability; check in authenticated GitHub UI. No transfers performed.'}

if __name__=='__main__':
    try:print(json.dumps(main(),ensure_ascii=False))
    except Exception as e:
        print(json.dumps({'error':str(e)[:200]}))
        sys.exit(3)
