#!/usr/bin/env python3
"""Ubuntu half of single transferred-repository remote migration.

No GitHub writes, repo sync, source build or AOSP manifest edits. Exact remote
URL matches only. Sensitive/ambiguous references fail closed. Results contain
metadata, never raw Git config file contents or GitHub credentials.
"""
from __future__ import annotations
import json, os, re, subprocess, sys, time
from pathlib import Path

NAME = re.compile(r'^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,78}[A-Za-z0-9])?$')
SHA = re.compile(r'^[a-f0-9]{40}$')
REF_REMOTE = re.compile(r'^remote\.([A-Za-z0-9_.-]+)\.url$')
EXCLUDED_DIRS = {'objects', 'lfs', 'hooks', 'logs', 'refs'}

class Stop(Exception): pass

def require(cond, msg):
    if not cond: raise Stop(msg)

def validate(payload):
    for key in ('repo','target'):
        val=payload.get(key)
        require(isinstance(val,str) and NAME.fullmatch(val) and '..' not in val,
                'Invalid repository or organization name')
    require(payload['target'].lower()!='deadknight','Source and target must differ')
    root=Path(payload.get('root',''))
    require(root.is_absolute() and root.is_dir() and '..' not in root.parts, 'Invalid existing AOSP root')
    require((root/'.repo').is_dir(),'AOSP .repo metadata missing')
    return root

def run(args, *, timeout=60):
    try:
        return subprocess.run(args,stdin=subprocess.DEVNULL,capture_output=True,text=True,
                              errors='replace',timeout=timeout,env=dict(os.environ,GIT_TERMINAL_PROMPT='0',GH_PROMPT_DISABLED='1'))
    except (OSError,subprocess.TimeoutExpired):
        raise Stop('A required Ubuntu tool is unavailable or timed out') from None

def api(endpoint):
    out=run(['gh','api',endpoint])
    require(out.returncode==0,'GitHub API verification failed; check Ubuntu gh connection (no retry)')
    try: data=json.loads(out.stdout)
    except ValueError:raise Stop('Invalid GitHub API response')
    require(isinstance(data,dict),'Unexpected GitHub API object')
    return data

def github_verify(payload, expected):
    repo=payload['repo']; target=payload['target']
    actor=api('user')
    require(str(actor.get('login','')).lower()=='deadknight','Expected Deadknight gh actor')
    membership=api('user/memberships/orgs/'+target)
    require(membership.get('role')=='admin' and membership.get('state')=='active',
            'Active organization admin membership required')
    actual=api('repos/'+target+'/'+repo)
    require(str(actual.get('full_name','')).lower()==(target+'/'+repo).lower(),
            'Destination repository full_name mismatch / redirected endpoint')
    require(actual.get('id')==expected.get('repository_id'),'Repository ID differs from original pilot')
    require(actual.get('private') is False and actual.get('visibility','public')=='public',
            'Pilot repository visibility changed')
    require(actual.get('fork') is False,'Pilot must remain non-fork')
    require(actual.get('default_branch')==expected.get('default_branch'),'Default branch changed')
    require(actual.get('permissions',{}).get('admin') is True,'New repository admin permission not confirmed')
    branch=expected.get('default_branch')
    require(isinstance(branch,str) and branch and '/' not in branch and '..' not in branch,
            'Invalid original branch name')
    from urllib.parse import quote
    commit=api('repos/'+target+'/'+repo+'/commits/'+quote(branch,safe=''))
    sha=commit.get('sha')
    require(isinstance(sha,str) and SHA.fullmatch(sha),'Invalid GitHub HEAD')
    require(sha==expected.get('source_head'),'Transferred repository HEAD differs from pre-transfer pilot')
    return {'repo_id':actual['id'],'head_sha':sha,'branch':branch,'visibility':'public',
            'source':'Deadknight/'+repo,'target':target+'/'+repo}

def expected_snapshot(expected,payload):
    require(isinstance(expected,dict),'Original V1.9 pilot snapshot required')
    require(expected.get('decision')=='READY_PILOT','Pilot was not READY')
    require(expected.get('source')=='Deadknight/'+payload['repo'],'Pilot source does not match')
    require(expected.get('target')==payload['target']+'/'+payload['repo'],'Pilot target does not match')
    require(isinstance(expected.get('repository_id'),int) and expected['repository_id']>0,
            'Invalid pilot repository ID')
    require(isinstance(expected.get('source_head'),str) and SHA.fullmatch(expected['source_head']),
            'Invalid pilot HEAD')
    require(expected.get('private') is False and expected.get('fork') is False and
            expected.get('visibility')=='public','Pilot metadata not safe for migration')
    require(not expected.get('aosp_manifest_refs'), 'Pilot snapshot references AOSP manifests')


def old_new_url(value, repo, target):
    """Recognize ONLY an exact old/target repo Git URL, preserving transport style."""
    pairs=(
        (f'https://github.com/Deadknight/{repo}',f'https://github.com/{target}/{repo}'),
        (f'git@github.com:Deadknight/{repo}',f'git@github.com:{target}/{repo}'),
        (f'ssh://git@github.com/Deadknight/{repo}',f'ssh://git@github.com/{target}/{repo}'),
    )
    for old,new in pairs:
        for suffix in ('','.git'):
            if value==old+suffix:return 'OLD',new+suffix
            if value==new+suffix:return 'NEW',new+suffix
    return None,None


def refers_to_exact_repository(url, repo, target):
    """Detect an unsupported reference to *this* repo, not a name prefix.

    GitHub repository names may contain '-', '_' and '.', so a simple
    substring search would incorrectly hold Car_Media for Car_MediaPrebuilt.
    A trailing slash/query/fragment is still a reference to the exact repo,
    but an unsupported URL shape must remain ambiguous and fail closed.
    """
    for owner in ('Deadknight', target):
        prefix = r'github\.com[/:]' + re.escape(owner) + '/' + re.escape(repo)
        trailing = r'(?:\.git)?(?=$|[/?#])'
        if re.search(prefix + trailing, url, re.IGNORECASE):
            return True
    return False


def git_remotes_from_config(fp):
    p=run(['git','config','--file',str(fp),'--null','--get-regexp',r'^remote\..*\.url$'],timeout=12)
    if p.returncode==1 and not p.stdout:return []
    require(p.returncode==0,'Unable to read Git remote metadata (Git config)')
    rows=[]
    for cell in p.stdout.split('\0'):
        if not cell:continue
        require('\n' in cell,'Malformed Git remote metadata')
        key,value=cell.split('\n',1)
        key=key.strip()
        m=REF_REMOTE.fullmatch(key)
        require(m is not None,'Unexpected Git remote property')
        rows.append((key,value.strip()))
    return rows


def scan_git_configs(root,repo,target):
    """Scope: repo-managed Git config files, not arbitrary home directories."""
    repo_root=root/'.repo'
    candidates=[]
    projects=repo_root/'projects'
    if projects.is_dir():
        candidates+=list(projects.rglob('config'))
    for candidate in (repo_root/'manifests.git/config',root/'.git/config'):
        if candidate.is_file():candidates.append(candidate)
    remotes=[]; ambiguous=[]
    for fp in sorted(set(candidates)):
        require(fp.is_file() and not fp.is_symlink(), 'Unsafe Git config file')
        require(fp.resolve().is_relative_to(root.resolve()), 'Git config escapes AOSP root')
        rel=fp.relative_to(root).as_posix()
        for key,url in git_remotes_from_config(fp):
            kind,replacement=old_new_url(url,repo,target)
            if kind is None:
                if refers_to_exact_repository(url, repo, target):
                    ambiguous.append({'config':rel,'remote':key,'reason':'unsupported Git URL form; manual review'})
                continue
            remotes.append({'config':rel,'remote':key,'state':kind,
                            'transport':'ssh' if url.startswith(('ssh:','git@')) else 'https',
                            'expected_old':url if kind=='OLD' else None,
                            'target_url':replacement})
    return remotes,ambiguous


def scan_manifests(root,repo,target):
    files=[];m=root/'.repo'
    for dirpath in (m/'local_manifests',m/'manifests'):
        if dirpath.is_dir():files+=list(dirpath.glob('*.xml'))
    if (m/'manifest.xml').exists():files.append(m/'manifest.xml')
    findings=[]
    for fp in sorted(set(files)):
        if not fp.is_file():continue
        require(fp.resolve().is_relative_to(root.resolve()),'Manifest path escapes AOSP root')
        try: content=fp.read_text('utf8')
        except (OSError,UnicodeError):raise Stop('Cannot read AOSP manifest')
        # Be conservative: ignore comments only when valid XML parsing is possible.
        try:
            import xml.etree.ElementTree as ET
            doc=ET.fromstring(content)
            elems=doc.iter()
            match=False
            for node in elems:
                if node.tag in ('project','remove-project','extend-project'):
                    name=node.attrib.get('name','');url=node.attrib.get('url','')
                    if name.casefold() in (repo.casefold(), ('Deadknight/'+repo).casefold(),
                                               (target+'/'+repo).casefold()) or refers_to_exact_repository(url, repo, target):
                        match=True
                elif node.tag=='remote':
                    fetch=node.attrib.get('fetch','')
                    # A shared owner remote is NOT safe to rewrite; flag it when target
                    # project name occurs anywhere in same manifest (even plain text).
                    if 'github.com/Deadknight' in fetch and re.search(r'(?<![\w.-])'+re.escape(repo)+r'(?![\w.-])',content):
                        match=True
            if match:findings.append(fp.relative_to(root).as_posix())
        except ET.ParseError:
            if repo in content:findings.append(fp.relative_to(root).as_posix())
    return sorted(set(findings))


def inspect(payload):
    root=validate(payload)
    expected=payload.get('pilot')
    expected_snapshot(expected,payload)
    verified=github_verify(payload,expected)
    remotes,ambiguous=scan_git_configs(root,payload['repo'],payload['target'])
    manifests=scan_manifests(root,payload['repo'],payload['target'])
    decision='READY_LOCAL_MIGRATION'
    if ambiguous:decision='HOLD_AMBIGUOUS_REMOTE'
    if manifests:decision='HOLD_MANIFEST_REFERENCES'
    return {'status':decision,'verified_github':verified,'remotes':remotes,
            'ambiguous_remote_refs':ambiguous,'manifest_refs':manifests,
            'scope':'Ubuntu AOSP .repo/projects Git configs and local/active manifest XML only',
            'no_manifest_mutation':True,'no_source_mutation':True}


def apply_changes(payload):
    plan=inspect(payload)
    if plan['status']!='READY_LOCAL_MIGRATION':return plan
    snapshot=payload.get('snapshot')
    require(isinstance(snapshot,dict),'Run arda org migrate --plan first')
    for key in ('verified_github','remotes','ambiguous_remote_refs','manifest_refs','scope'):
        require(plan[key]==snapshot.get(key),'Migration plan stale ('+key+'); inspect again')
    expected='Deadknight/'+payload['repo']+' -> '+payload['target']+'/'+payload['repo']
    require(payload.get('confirm')==expected,'Exact --confirm required')
    root=Path(payload['root']); changed=[]
    try:
        for rec in plan['remotes']:
            if rec['state']!='OLD':continue
            fp=root/rec['config']
            require(fp.is_file() and not fp.is_symlink() and fp.resolve().is_relative_to(root.resolve()),
                    'Git config location changed')
            present=dict(git_remotes_from_config(fp))
            require(present.get(rec['remote'])==rec['expected_old'],
                    'Git remote URL changed since plan')
            new=rec['target_url']
            p=run(['git','config','--file',str(fp),'--replace-all',rec['remote'],new],timeout=12)
            require(p.returncode==0,'Failed to update Git remote')
            changed.append(rec)
            require(dict(git_remotes_from_config(fp)).get(rec['remote'])==new,
                    'Updated Git remote failed verification')
        # Post-check verifies original GitHub repo identity is still the same.
        again=github_verify(payload,payload['pilot'])
        require(again==plan['verified_github'],'Destination SHA/identity changed during migration')
        return {**plan,'status':'LOCAL_MIGRATION_VERIFIED',
                'changed_remote_count':len(changed),
                'already_new_remote_count':sum(x['state']=='NEW' for x in plan['remotes']),
                'manifest_changed':False}
    except Exception:
        rollback_errors=[]
        for rec in reversed(changed):
            fp=root/rec['config']
            p=run(['git','config','--file',str(fp),'--replace-all',rec['remote'],rec['expected_old']],timeout=12)
            if p.returncode or dict(git_remotes_from_config(fp)).get(rec['remote'])!=rec['expected_old']:
                rollback_errors.append(rec['config']+':'+rec['remote'])
        if rollback_errors:
            raise Stop('Migration failed; LOCAL ROLLBACK INCOMPLETE, inspect remotes: '+', '.join(rollback_errors))
        raise


def main():
    payload=json.loads(sys.stdin.read())
    return apply_changes(payload) if payload.get('apply') else inspect(payload)

if __name__=='__main__':
    try:
        print(json.dumps(main(),ensure_ascii=False,sort_keys=True))
    except Exception as e:
        print(json.dumps({'status':'STOP','error':str(e)[:350],
                          'local_remote_changes_may_be_partial':True if 'ROLLBACK INCOMPLETE' in str(e) else False},
                         ensure_ascii=False,sort_keys=True))
        sys.exit(3)
