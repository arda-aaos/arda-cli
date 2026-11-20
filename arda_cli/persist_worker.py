#!/usr/bin/env python3
"""ARDA v0.8 Ubuntu-only Git publisher. Executed over authenticated SSH.

This is NOT an Android updater. It never builds, syncs, deploys, resets or reboots.
A successful call publishes one source checkpoint and a separate manifest release.
Partial remote success is intentionally reported, not concealed or force-rolled back.
"""
from __future__ import annotations

import base64
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess as sp
import sys
import tempfile
import xml.etree.ElementTree as ET

OWNER = 'arda-aaos'
PARENT_RELEASE = '2026-11-16-v49.7'
MANIFEST_REPO = 'arda-aaos/arda-aaos-manifest'
BASES = {
    'packages/apps/Car/Cluster': '7244742c0268e1a1f6e88f5b2e1df0c0ec2c825a',
    'external/libudev-zero': '6f093b428ecae5138654b61d7f29871cef8739dc',
}
TARGETS = {
    'DirectRenderingCluster': {'source':'packages/apps/Car/Cluster','strategy':'PATCH','prefix':'DirectRenderingCluster/'},
    'CarSystemUI': {'source':'packages/apps/Car/SystemUI','strategy':'FORK',
                    'github':'arda-aaos/android_packages_apps_Car_SystemUI','manifest_project':'android_packages_apps_Car_SystemUI'},
    'arda-connectivityd': {'source':'vendor/arda/ardaplatform','strategy':'DIRECT',
                           'github':'arda-aaos/android_vendor_arda_ardaplatform'},
    'ArdaPlatform': {'source':'ArdaPlatform','strategy':'DIRECT','github':'arda-aaos/ArdaPlatform'},
    # CarLauncher has no remotely verified branch/pin and is intentionally not publish-enabled.
    # Mac-only ArdaPlatform requires a separate, guarded Git-bundle transfer.
}
PRIVATE_MARKERS = (b'-----BEGIN PRIVATE KEY-----', b'-----BEGIN RSA PRIVATE KEY-----',
                   b'-----BEGIN EC PRIVATE KEY-----', b'-----BEGIN OPENSSH PRIVATE KEY-----',
                   b'-----BEGIN ENCRYPTED PRIVATE KEY-----', b'-----BEGIN DSA PRIVATE KEY-----',
                   b'-----BEGIN PGP PRIVATE KEY BLOCK-----')
SENSITIVE = re.compile(r'(?i)(^|/)(\.ssh|signing|secrets?|credentials?|\.env(?:\.[^/]*)?|private[-_]?keys?)(/|$)|(?:^|/)[^/]*(?:release[_-]?key|upload[_-]?key|private[_-]?key)[^/]*$|\.(?:pk8|jks|keystore|p12|pfx|p8|kdbx|key|asc|gpg)$')
EXCLUDED = {'.arda-backups','.git','.repo','out','build','__pycache__','.gradle','.idea','.vscode','.DS_Store'}
SHA = re.compile(r'^[0-9a-f]{40}$')
TOKEN_PATTERNS = (re.compile(rb'github_pat_[A-Za-z0-9_]{20,}'),
                  re.compile(rb'ghp_[A-Za-z0-9]{30,}'),
                  re.compile(rb'AKIA[0-9A-Z]{16}'))
ENV = dict(os.environ, GIT_TERMINAL_PROMPT='0', GH_PROMPT_DISABLED='1', GIT_OPTIONAL_LOCKS='0', GIT_LFS_SKIP_SMUDGE='1')

class Stop(Exception): pass

def require(cond, msg):
    if not cond: raise Stop(msg)

def say(msg): print('[ARDA PERSIST] '+msg, flush=True)

def cmd(*args, cwd=None, timeout=120, output=False, check=True, env=None):
    try:
        p=sp.run([str(x) for x in args],cwd=cwd,env=(env or ENV),stdin=sp.DEVNULL,
                 stdout=sp.PIPE,stderr=sp.PIPE,timeout=timeout)
    except (OSError,sp.TimeoutExpired) as exc:
        raise Stop(f'Unable to run {args[0]}: {type(exc).__name__}') from exc
    if check and p.returncode:
        # Tool errors can contain credentials or secret source lines. Never include them in reports.
        raise Stop(f'{args[0]} command failed (exit={p.returncode})')
    return p if output else p.stdout.decode('utf-8','replace').strip()

def git(repo, *args, **kwargs): return cmd('git', *args,cwd=repo,**kwargs)

def sha256(b):return hashlib.sha256(b).hexdigest()

def git_status(repo):
    raw=git(repo,'status','--porcelain=v1','-z','--untracked-files=all',output=True).stdout
    if not raw:return []
    require(raw.endswith(b'\0'),'Incomplete git status')
    entries=raw[:-1].split(b'\0'); out=[];i=0
    while i<len(entries):
        cell=entries[i]
        require(len(cell)>=4 and cell[2:3]==b' ','Malformed git status entry')
        code=cell[:2].decode('ascii','replace')
        require('R' not in code and 'C' not in code,'Renames/copies require manual review')
        path=cell[3:].decode('utf-8','strict')
        require(safe_relative(path),'Unsafe path in git status')
        out.append((code,path));i+=1
    return out

def safe_relative(s):
    return bool(s and '\\' not in s and '\0' not in s and not s.startswith('/') and
                all(p not in ('','.','..') for p in s.split('/')) and
                all(ord(c)>=32 for c in s))

def path_kind(path):
    if SENSITIVE.search(path) or path.endswith('.pem') and path != 'updater/res/raw/arda_manifest_pubkey.pem':
        return 'SENSITIVE'
    if set(path.split('/')) & EXCLUDED or path.endswith(('~','.bak','.orig','.swp','.pyc')):
        return 'BACKUP'
    return 'SOURCE'

def validate_pubkey(raw):
    require(len(raw)<8192, 'Unexpected public key size')
    require(re.fullmatch(rb'-----BEGIN (?:PUBLIC KEY|RSA PUBLIC KEY)-----\r?\n(?:[A-Za-z0-9+/=]{1,100}\r?\n)+-----END (?:PUBLIC KEY|RSA PUBLIC KEY)-----\r?\n?',raw) is not None,
            'Manifest PEM is not a simple public key')
    with tempfile.NamedTemporaryFile(mode='wb',suffix='.pem',delete=True) as f:
        f.write(raw);f.flush()
        result=cmd('openssl','pkey','-pubin','-in',f.name,'-noout',check=False,output=True,timeout=15)
        if result.returncode!=0 and b'RSA PUBLIC KEY' in raw:
            result=cmd('openssl','rsa','-RSAPublicKey_in','-in',f.name,'-noout',check=False,output=True,timeout=15)
        require(result.returncode==0, 'Manifest PEM public key parse failed')

def inspect_bytes(raw, path):
    require(len(raw)<=100_000_000, 'Source blob exceeds 100MB: '+path)
    if path.endswith('.pem'):
        require(path=='updater/res/raw/arda_manifest_pubkey.pem','Unapproved PEM file')
        validate_pubkey(raw)
    else:
        require(not any(x in raw for x in PRIVATE_MARKERS),'Private key marker found in new content: '+path)
        require(not any(p.search(raw) for p in TOKEN_PATTERNS),'Credential token signature detected in new source: '+path)
    require(not SENSITIVE.search(path),'Sensitive path excluded from publication')

def safe_change_paths(repo, entries, target):
    selected=[]; ignored=[]
    for code,path in entries:
        require(code[0] in (' ','?'), 'Staged content exists; inspect the Git index manually')
        if code=='??' and path.startswith('updater/signing/'):
            ignored.append(path)
            continue
        kind=path_kind(path)
        if kind=='BACKUP': ignored.append(path);continue
        require(kind!='SENSITIVE','Sensitive untracked/modified file: '+path)
        if target['strategy']=='PATCH':
            require(path.startswith(target['prefix']), 'Patch strategy change outside managed module: '+path)
        if target['source']=='vendor/arda/ardaplatform':
            # Source/update manager code is in this repo, but signing never is.
            require(not path.startswith('updater/signing/'),'Signing material must stay local')
        full=repo/path
        require(full.resolve().is_relative_to(repo.resolve()),'Source path escapes Git root')
        require(not full.is_symlink(), 'Symlink change not accepted: '+path)
        if full.exists():
            require(full.is_file(), 'Only regular source files supported: '+path)
            require(full.stat().st_size<=100_000_000,'Source file too large: '+path)
            inspect_bytes(full.read_bytes(),path)
        selected.append(path)
    return sorted(set(selected)),ignored

def remote_branch(url):
    rows=cmd('git','ls-remote','--heads',url,'main',timeout=100).splitlines()
    require(len(rows)==1 and rows[0].endswith('refs/heads/main'), 'Expected GitHub main branch missing')
    sha=rows[0].split()[0]
    require(SHA.fullmatch(sha) is not None,'Remote SHA not valid')
    return sha

def same_remote(actual,expected):
    # No URL with embedded credentials/tokens; no cross-owner remotes.
    actual=actual.rstrip('/').removesuffix('.git')
    expected=expected.rstrip('/').removesuffix('.git')
    if actual == expected:return True
    return actual == f'git@github.com:{OWNER}/{expected.split("/")[-1]}' if expected.startswith('https://github.com/') else False

def check_remote_owner(repo,target):
    expected='https://github.com/'+target['github']+'.git'
    remotes=git(repo,'remote').splitlines()
    choices=[]
    for name in remotes:
        url=git(repo,'remote','get-url',name)
        if same_remote(url,expected):choices.append(name)
    require(len(choices)==1,'Expected unique organization Git remote not found')
    return choices[0],expected


def require_org_repo_identity(repository, *, manifest=False):
    """Fail closed if GitHub does not report the exact organization and permission.

    An org is not a user login; gh api user may still identify its human member.
    This verifies ownership, not historical transfer provenance (audited separately).
    """
    require(re.fullmatch(r'arda-aaos/[A-Za-z0-9_.-]+', repository) is not None,
            'Unexpected repository identity')
    raw=cmd('gh','api','repos/'+repository,timeout=35)
    obj=json.loads(raw)
    require(obj.get('full_name')==repository,'GitHub repository full name mismatch')
    require((obj.get('owner') or {}).get('login')=='arda-aaos','GitHub repository owner mismatch')
    require(type(obj.get('id')) is int and obj['id']>0,'GitHub repository ID missing')
    if manifest:
        require(obj['id']==1291398982,'Manifest GitHub repository ID mismatch')
    perms=obj.get('permissions') or {}
    require(perms.get('push') is True or perms.get('admin') is True,
            'Authenticated GitHub member has no confirmed push permission')
    return obj['id']

def require_explicit_persist_gate(payload):
    """No source publication before a distinct, reviewed org manifest commit."""
    expected=payload.get('approved_manifest_head')
    require(isinstance(expected,str) and SHA.fullmatch(expected),
            'Owner-aware persist HOLD: approved new manifest SHA missing')
    require(expected!='a85ead3d1d0973e73d7ff34a0cd2d1d67f1ceb0f',
            'Owner-aware persist HOLD: pre-migration manifest SHA disallowed')
    live=remote_branch('https://github.com/'+MANIFEST_REPO+'.git')
    require(live==expected,'Owner-aware persist HOLD: manifest HEAD changed')
    require_org_repo_identity(MANIFEST_REPO,manifest=True)

def scan_unpublished_history(repo, base):
    # Scan the complete future pushed objects that are not already on remote main.
    commits=git(repo,'rev-list','HEAD','^'+base).splitlines()
    for cid in commits:
        raw=git(repo,'cat-file','commit',cid,output=True).stdout
        require(not any(x in raw for x in PRIVATE_MARKERS),'Private key marker in unpublished commit metadata')
        require(not any(p.search(raw) for p in TOKEN_PATTERNS),'Credential token in unpublished commit metadata')
    ids=git(repo,'rev-list','--objects','HEAD','^'+base).splitlines()
    seen=set();count=0
    for row in ids:
        oid=row.split()[0]
        if oid in seen:continue
        seen.add(oid)
        parts=row.split(' ',1)
        if len(parts)==2:
            require(path_kind(parts[1])!='SENSITIVE', 'Sensitive path in unpublished Git history')
        typ=git(repo,'cat-file','-t',oid)
        if typ!='blob':continue
        size=int(git(repo,'cat-file','-s',oid))
        require(size<=100_000_000,'Large unpublished git blob requires review')
        data=git(repo,'cat-file','blob',oid,output=True,timeout=60).stdout
        require(not any(x in data for x in PRIVATE_MARKERS),'Private key marker found in unpublished Git object')
        require(not any(p.search(data) for p in TOKEN_PATTERNS),'Credential token in unpublished Git object')
        count+=1
    return count

def prepare_source(repo,target):
    before=git(repo,'rev-parse','HEAD')
    require(SHA.fullmatch(before) is not None,'Invalid local HEAD')
    require(git(repo,'rev-parse','--show-toplevel')==str(repo.resolve()),'Nested or unexpected Git root')
    records=git_status(repo)
    changed,ignored=safe_change_paths(repo,records,target)
    require(len(changed)<500,'Too many source changes for automatic publishing')
    return before,changed,ignored

def create_source_commit(repo,paths,label):
    if not paths:return git(repo,'rev-parse','HEAD'),False
    git(repo,'add','--',*paths)
    expected=set(paths)
    staged=git(repo,'diff','--cached','--name-only','-z',output=True).stdout
    names={x.decode('utf8') for x in staged.split(b'\0') if x}
    require(names==expected,'Staged path set mismatch; stopped before commit')
    delta=git(repo,'diff','--cached','--binary',output=True).stdout
    require(not any(x in delta for x in PRIVATE_MARKERS),'Private marker in staged Git diff')
    git(repo,'-c','user.name=ARDA Source Publisher','-c','user.email=arda-source@users.noreply.github.com',
        '-c','commit.gpgsign=false','commit','-m','ARDA: '+label,timeout=120)
    result=git(repo,'rev-parse','HEAD')
    require(not git(repo,'diff','--cached','--name-only'), 'Index not clean after commit')
    return result,True

def replay_patch(repo,base,head):
    require(SHA.fullmatch(base) and SHA.fullmatch(head),'Invalid replay SHA')
    require(git(repo,'cat-file','-t',base)=='commit','Missing upstream base commit')
    ancestor=cmd('git','merge-base','--is-ancestor',base,head,cwd=repo,output=True,check=False)
    require(ancestor.returncode==0,'Current patch does not descend from pinned upstream base')
    patch=git(repo,'diff','--binary','--full-index',base,head,output=True).stdout
    require(0<len(patch)<30_000_000,'Empty or oversized consolidated patch')
    require(not any(s in patch for s in PRIVATE_MARKERS),'Private key marker in consolidated patch')
    target_tree=git(repo,'rev-parse',head+'^{tree}')
    with tempfile.TemporaryDirectory(prefix='arda-patch-replay-') as tmp:
        idx=Path(tmp)/'index'
        env=dict(ENV,GIT_INDEX_FILE=str(idx))
        cmd('git','read-tree',base,cwd=repo,env=env)
        p=sp.run(['git','apply','--cached','--check','-'],input=patch,cwd=repo,env=env,
                 stdout=sp.PIPE,stderr=sp.PIPE,timeout=70)
        require(p.returncode==0,'Clean patch replay check failed')
        p=sp.run(['git','apply','--cached','-'],input=patch,cwd=repo,env=env,
                 stdout=sp.PIPE,stderr=sp.PIPE,timeout=70)
        require(p.returncode==0,'Clean patch replay application failed')
        actual=cmd('git','write-tree',cwd=repo,env=env)
    require(actual==target_tree,'Clean patch replay tree SHA mismatch')
    return patch,target_tree

def apply_script(base_tree_map):
    # A replay script is an explicit post-sync step; never invoked in this publisher.
    lines=['#!/usr/bin/env bash','set -euo pipefail',
           'ROOT="${1:?Usage: apply-sources.sh /path/to/aosp-root}"',
           'BUNDLE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"',
           '# Verify every project before touching any source tree.']
    parts=[]
    for path,base,patchname,tree in base_tree_map:
        require(all(safe_relative(s) for s in (path,patchname)) and SHA.fullmatch(base) and SHA.fullmatch(tree),
                'Invalid replay script source')
        # constant known paths; no untrusted interpolation/shell escapes
        parts.append((path,base,patchname,tree))
    for path,base,patchname,tree in parts:
        lines+= [f'target="$ROOT/{path}"; patch="$BUNDLE/patches/{patchname}"',
                 'test -f "$patch" && test -d "$target" || { echo "MISSING_PATCH_OR_SOURCE" >&2; exit 3; }',
                 'test -z "$(git -C "$target" status --porcelain -uall)" || { echo "DIRTY_SOURCE" >&2; exit 3; }',
                 'current="$(git -C "$target" rev-parse HEAD)"',
                 'tree="$(git -C "$target" rev-parse HEAD^{tree})"',
                 f'if [[ "$tree" != "{tree}" ]]; then',
                 f'  [[ "$current" == "{base}" ]] || {{ echo "BASE_MISMATCH" >&2; exit 3; }}',
                 '  git -C "$target" apply --check --cached "$patch"',
                 'fi']
    for path,base,patchname,tree in parts:
        lines += [f'target="$ROOT/{path}"; patch="$BUNDLE/patches/{patchname}"',
                  'current_tree="$(git -C "$target" rev-parse HEAD^{tree})"',
                  f'if [[ "$current_tree" != "{tree}" ]]; then',
                  '  git -C "$target" apply --index "$patch"',
                  f'  [[ "$(git -C "$target" write-tree)" == "{tree}" ]] || {{ echo "TREE_MISMATCH" >&2; exit 4; }}',
                  '  git -C "$target" -c commit.gpgsign=false -c user.name="ARDA Source Publisher" -c user.email="arda-source@users.noreply.github.com" commit -m "ARDA: verified source patch" >/dev/null',
                  'fi']
    lines += ['echo ARDA_SOURCE_REPLAY=PASS']
    return ('\n'.join(lines)+'\n').encode()


def latest_release(manifest):
    ptr=manifest/'releases/arda-cli-latest.json'
    if not ptr.is_file():return PARENT_RELEASE
    doc=json.loads(ptr.read_text('utf8'))
    value=doc.get('release','')
    require(re.fullmatch(r'20[0-9]{2}-[0-9]{2}-[0-9]{2}-cli-v1\.(?:7|8)-[a-z0-9-]+-[a-f0-9]{10}', value) is not None,
            'Malformed manifest latest-release pointer')
    return value

def existing_release(manifest, parent):
    prior=manifest/'releases'/parent
    require(prior.is_dir(),'Expected V49.7 parent release not found')
    files={}
    for p in prior.rglob('*'):
        if p.is_symlink():raise Stop('Manifest release symlink not permitted')
        if p.is_file():files[p.relative_to(prior).as_posix()]=p.read_bytes()
    required=('patches/cluster-v42.patch','patches/libudev-zero.patch',
              'metadata/source-pins.json','locks/source-heads.tsv',
              'manifests/30-v49.7-upstream-pins.xml')
    require(all(p in files for p in required),'Incomplete V49.7 parent release')
    return files

def manifest_release(root, module, target, head, patch, patch_tree, newname, manifest):
    parent=latest_release(manifest)
    files=existing_release(manifest,parent)
    data=json.loads(files['metadata/source-pins.json'])
    require(data.get('car_cluster',{}).get('base_sha')==BASES['packages/apps/Car/Cluster'],
            'V49.7 Cluster upstream SHA unexpectedly changed')
    require(data.get('libudev_zero',{}).get('base_sha')==BASES['external/libudev-zero'],
            'V49.7 libudev base unexpectedly changed')
    if target['strategy']=='PATCH':
        files['patches/cluster-v42.patch']=patch
        data['car_cluster']['local_commit_sha']=head
        data['car_cluster']['post_patch_tree']=patch_tree
        data['car_cluster']['patch_sha256']=sha256(patch)
    elif target['source']=='ArdaPlatform':
        require(data.get('mac_ardaplatform',{}).get('repo') in ('Deadknight/ArdaPlatform','arda-aaos/ArdaPlatform'),
                'ArdaPlatform release metadata ownership not verified')
        data['mac_ardaplatform']['repo']='arda-aaos/ArdaPlatform'
        data['mac_ardaplatform']['sha']=head
        data['mac_ardaplatform']['verified_remote']=True
    elif target['source']=='vendor/arda/ardaplatform':
        data['vendor_arda_ardaplatform']['sha']=head
        files['locks/independent-vendor-ardaplatform.sha']=(head+'\n').encode()
        # If vendor is Repo-managed, its overlay pin must advance too.
        xml=ET.fromstring(files['manifests/30-v49.7-upstream-pins.xml'])
        vendors=[node for node in xml.findall('extend-project') if node.get('path')==target['source']]
        require(len(vendors)<=1,'Duplicate vendor project in manifest overlay')
        if vendors:
            recorded=data['vendor_arda_ardaplatform'].get('repo_project_name')
            require(recorded and vendors[0].get('name')==recorded,
                    'Vendor manifest project name does not match release metadata')
            vendors[0].set('revision',head)
            files['manifests/30-v49.7-upstream-pins.xml']=ET.tostring(xml,encoding='utf-8',xml_declaration=True)+b'\n'
    else:
        # Fork is pinned by the exact existing project name in this overlay.
        xml=ET.fromstring(files['manifests/30-v49.7-upstream-pins.xml'])
        matches=[p for p in xml.findall('extend-project') if p.get('path')==target['source']]
        require(len(matches)<=1, 'Duplicate fork project in parent overlay')
        if matches:
            require(matches[0].get('name')==target['manifest_project'],'Fork project identity changed in parent overlay')
            matches[0].set('revision',head)
        else:
            ET.SubElement(xml,'extend-project',{'name':target['manifest_project'],
                                                 'path':target['source'],'revision':head})
        files['manifests/30-v49.7-upstream-pins.xml']=ET.tostring(xml,encoding='utf-8',xml_declaration=True)+b'\n'
    lock=files['locks/source-heads.tsv'].decode('utf8')
    require(lock.startswith('path\tsha\n'),'Invalid source-heads lock')
    rows={}
    for line in lock.splitlines()[1:]:
        if not line:continue
        k,sep,v=line.partition('\t')
        require(sep=='\t' and SHA.fullmatch(v),'Invalid source lock row')
        rows[k]=v
    if target['source']!='ArdaPlatform':
        rows[target['source']]=head
    files['locks/source-heads.tsv']=('path\tsha\n'+''.join(f'{p}\t{sha}\n' for p,sha in sorted(rows.items()))).encode()
    # The release contains all of the parent patches, not an ever-growing patch chain.
    lib=data['libudev_zero']; cluster=data['car_cluster']
    steps=[('external/libudev-zero',lib['base_sha'],'libudev-zero.patch',lib['post_patch_tree']),
           ('packages/apps/Car/Cluster',cluster['base_sha'],'cluster-v42.patch',cluster['post_patch_tree'])]
    files.pop('scripts/apply-v49.7.sh',None)
    files['scripts/apply-sources.sh']=apply_script(steps)
    # No reliance on a dated parent script to replay Cluster; consolidated patch from one base.
    data['release']=newname
    data['parent_release']=parent
    data['changed_module']=module
    data['source_only_not_build_attested']=True
    data['security_note']='New payload and unpublished Git objects checked for private-key markers; existing remote history is not fully audited.'
    files['metadata/source-pins.json']=(json.dumps(data,indent=2,sort_keys=True)+'\n').encode()
    files['README.md']=(f'# ARDA AAOS source checkpoint {newname}\n\n'
        f'Parent: `{parent}`. Changed module: `{module}`; Git HEAD: `{head}`.\n\n'
        'Source-only checkpoint, NOT a validated image or deployment. No build/test is asserted.\n'
        'Use this release overlay as a Repo local manifest BEFORE source sync.\n'
        'On clean source, run `bash scripts/apply-sources.sh /path/to/aosp-root` to replay BOTH patches.\n'
        'Never run this script on the working AAOS source without an explicit recovery plan.\n'
        'The legacy September bootstrap and V49.7 checkpoint remain untouched.\n').encode()
    for name,body in files.items():
        require(safe_relative(name),'Unsafe manifest release path')
        require(not SENSITIVE.search(name) and not (set(PurePosixPath(name).parts) & {'.git','.repo','signing'}),
                'Secret/metadata path in release')
        require(not any(marker in body for marker in PRIVATE_MARKERS),'Private key marker in release asset')
    return files

def publish_manifest(files,name,manifest):
    dest=manifest/'releases'/name
    require(not dest.exists(),'Release path already exists. Refusing overwrite')
    paths=[]
    for rel,data in files.items():
        p=dest/rel
        p.parent.mkdir(parents=True,exist_ok=True)
        p.write_bytes(data)
        paths.append((Path('releases')/name/rel).as_posix())
    latest=manifest/'releases/arda-cli-latest.json'
    latest.write_text(json.dumps({'release':name},sort_keys=True)+'\n',encoding='utf8')
    paths.append('releases/arda-cli-latest.json')
    git(manifest,'add','--',*sorted(paths))
    staged={x.decode('utf8') for x in git(manifest,'diff','--cached','--name-only','-z',output=True).stdout.split(b'\0') if x}
    require(staged==set(paths),'Manifest staged files differ from new release assets')
    git(manifest,'-c','user.name=ARDA Source Publisher',
        '-c','user.email=arda-source@users.noreply.github.com',
        '-c','commit.gpgsign=false','commit','-m','ARDA: source checkpoint '+name)
    new=git(manifest,'rev-parse','HEAD')
    git(manifest,'push','origin',new+':refs/heads/main',timeout=480)
    require(remote_branch('https://github.com/'+MANIFEST_REPO+'.git')==new,'Manifest push SHA verification failed')
    return new

def run_publish(payload):
    module=payload.get('module')
    require(module in TARGETS,'Module not currently enabled for safe publication')
    target=TARGETS[module]
    require(payload.get('strategy')==target['strategy'],'Strategy mismatch from local plan')
    root=Path(payload['root'])
    require(root.is_absolute() and '..' not in root.parts and (root/'.repo').is_dir(),'Invalid AOSP root')
    repo=(root/target['source']).resolve()
    require(repo.is_dir() and repo.is_relative_to(root.resolve()),'Source repo missing or escapes AOSP root')
    require(shutil.which('git') and shutil.which('gh'),'Git and gh required on Ubuntu')
    if target['strategy']=='FORK':
        require(shutil.which('repo'),'Repo metadata command required for fork pin verification')
        resolved=cmd('repo','manifest','-r',cwd=root,timeout=180,output=True,check=False)
        require(resolved.returncode==0,'Unable to read resolved AOSP manifest')
        xml=ET.fromstring(resolved.stdout)
        projects=[x for x in xml.findall('.//project') if x.get('path')==target['source']]
        require(len(projects)==1 and projects[0].get('name')==target['manifest_project'],
                'Fork project name does not match resolved manifest')
    require_explicit_persist_gate(payload)
    if target['strategy']!='PATCH':
        require_org_repo_identity(target['github'])
    require(cmd('gh','auth','status',check=False,output=True,timeout=30).returncode==0,'GitHub gh authentication unavailable')
    cache=Path.home()/'.cache/arda-cli';cache.mkdir(parents=True,exist_ok=True)
    with (cache/'persist.lock').open('a+') as lock:
        try: fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError: raise Stop('Another ARDA persist operation is running')
        before,changed,ignored=prepare_source(repo,target)
        expected=payload.get('expected_head')
        require(before==expected,'Ubuntu Git HEAD changed since Mac persist plan')
        if not changed and (payload.get('release_status')=='MATCH'):
            return {'status':'NO_NEW_SOURCE_CHANGES','module':module,'git_head':before,'new_manifest':None}
        remote_name=None;remote_url=None;old_remote=None
        if target['strategy']!='PATCH':
            remote_name,remote_url=check_remote_owner(repo,target)
            old_remote=remote_branch(remote_url)
            require(git(repo,'cat-file','-t',old_remote)=='commit','Missing remote base commit in local Git')
            require(cmd('git','merge-base','--is-ancestor',old_remote,before,cwd=repo,check=False,output=True).returncode==0,
                    'Remote main is not ancestor of current local branch')
        else:
            base=BASES[target['source']]
            require(git(repo,'cat-file','-t',base)=='commit','Pinned Cluster base is unavailable')
            require(cmd('git','merge-base','--is-ancestor',base,before,cwd=repo,check=False,output=True).returncode==0,
                    'Cluster HEAD not descended from expected upstream SHA')
        # Preflight manifest remotely BEFORE any source commit/push.
        manifesturl='https://github.com/'+MANIFEST_REPO+'.git'
        manifest_before=remote_branch(manifesturl)
        with tempfile.TemporaryDirectory(prefix='arda-cli-persist-') as temp:
            mirror=Path(temp)/'manifest'
            cmd('gh','repo','clone',MANIFEST_REPO,str(mirror),'--','--quiet',timeout=240)
            require(git(mirror,'rev-parse','HEAD')==manifest_before,'Manifest changed between ls-remote and clone')
            require(same_remote(git(mirror,'remote','get-url','origin'),manifesturl),
                    'Manifest clone origin remote mismatch')
            require(not git_status(mirror),'Manifest clone has local changes')
            parent=latest_release(mirror)
            parent_assets=existing_release(mirror,parent)
            parent_metadata=json.loads(parent_assets['metadata/source-pins.json'])
            old_rows={}
            for line in parent_assets['locks/source-heads.tsv'].decode('utf8').splitlines()[1:]:
                if line and '\t' in line:
                    k,v=line.split('\t',1);old_rows[k]=v
            pin=(parent_metadata.get('car_cluster',{}).get('local_commit_sha') if target['strategy']=='PATCH'
                 else parent_metadata.get('vendor_arda_ardaplatform',{}).get('sha') if module=='arda-connectivityd'
                 else old_rows.get(target['source']))
            if pin and SHA.fullmatch(pin):
                require(cmd('git','merge-base','--is-ancestor',pin,before,cwd=repo,check=False,output=True).returncode==0,
                        'Local source is older/divergent from last published checkpoint')
                if not changed and pin==before:
                    return {'status':'NO_NEW_SOURCE_CHANGES','module':module,'git_head':before,
                            'latest_manifest_release':parent,'new_manifest':None}
            # HEAD may already be pushed after an interrupted earlier attempt.
            # If it differs from the recorded checkpoint, still publish the manifest.
            # Unpublished commits might be present; scan them before any push.
            if target['strategy']!='PATCH':
                scanned=scan_unpublished_history(repo,old_remote)
                say(f'Unpublished historical Git blobs screened: {scanned}')
            # Actual local source commit and release generation begin here.
            require(git(repo,'rev-parse','HEAD')==before,'Source HEAD changed mid-preflight')
            new_head,created=create_source_commit(repo,changed,module+' source update')
            if target['strategy']!='PATCH':
                require(cmd('git','merge-base','--is-ancestor',old_remote,new_head,cwd=repo,check=False,output=True).returncode==0,
                        'Remote main diverged before source push')
                scan_unpublished_history(repo,old_remote)
            else:
                patch,tree=replay_patch(repo,BASES[target['source']],new_head)
                say('Consolidated source patch replay verified against exact Git tree')
            version=dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%d')+'-cli-v1.8-'+re.sub('[^a-z0-9]','-',module.lower())+'-'+new_head[:10]
            files=manifest_release(root,module,target,new_head,patch if target['strategy']=='PATCH' else None,
                                   tree if target['strategy']=='PATCH' else None,version,mirror)
            require(not (mirror/'releases'/version).exists(),'Release already published; stop and audit')
            # Git remote may change during local work; verify again before publishing.
            require(remote_branch(manifesturl)==manifest_before,'Manifest main changed during preflight')
            if target['strategy']!='PATCH':
                require(remote_branch(remote_url)==old_remote,'Source remote main changed during preflight')
                if old_remote!=new_head:
                    git(repo,'push',remote_url,new_head+':refs/heads/main',timeout=480)
                    require(remote_branch(remote_url)==new_head,'Source GitHub SHA mismatch after push')
                    say('SOURCE_PUSH_VERIFIED='+new_head)
            # From this point, if manifest push fails source may already be pushed.
            # Report the partial state; never force push or reset/revert automatically.
            manifest_sha=publish_manifest(files,version,mirror)
            say('MANIFEST_PUSH_VERIFIED='+manifest_sha)
            return {'status':'PASS_PUBLISHED','module':module,'source_strategy':target['strategy'],
                    'previous_head':before,'source_head':new_head,'source_commit_created':created,
                    'manifest_release':version,'manifest_sha':manifest_sha,
                    'source_remote_sha':new_head if target['strategy']!='PATCH' else None,
                    'ignored_backup_paths':len(ignored), 'source_only_not_build_attested':True,
                    'repo_sync':False,'build':False,'device_install':False,'reboot':False}



def run_publish_mac(payload):
    """Ubuntu side, from a Mac-created incremental Git bundle. Never touches Mac source."""
    module=payload.get('module')
    require(module=='ArdaPlatform' and payload.get('strategy')=='DIRECT','Unsupported Mac project')
    source_head=payload.get('expected_head')
    base_sha=payload.get('remote_base')
    require(isinstance(source_head,str) and SHA.fullmatch(source_head),'Invalid Mac commit')
    require(isinstance(base_sha,str) and SHA.fullmatch(base_sha),'Invalid remote base')
    bundle_text=payload.get('bundle_path')
    if source_head!=base_sha:
        require(isinstance(bundle_text,str) and re.fullmatch(r'/tmp/arda-mac-persist\.[A-Za-z0-9_]{8,16}/source\.bundle',bundle_text),
                'Unexpected transfer path')
        bundle=Path(bundle_text)
        require(bundle.is_file() and not bundle.is_symlink() and bundle.stat().st_size<150_000_000,
                'Missing/oversized/symlink Git bundle')
    else:
        require(bundle_text is None,'Unexpected bundle for unchanged source')
    require(shutil.which('git') and shutil.which('gh'),'Ubuntu needs Git and gh')
    require_explicit_persist_gate(payload)
    require_org_repo_identity(TARGETS['ArdaPlatform']['github'])
    cache=Path.home()/'.cache/arda-cli';cache.mkdir(parents=True,exist_ok=True)
    with (cache/'persist.lock').open('a+') as lock:
        try: fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError: raise Stop('Another persist is running')
        src='arda-aaos/ArdaPlatform'
        source_url='https://github.com/'+src+'.git'
        manifest_url='https://github.com/'+MANIFEST_REPO+'.git'
        remote_current=remote_branch(source_url)
        require(remote_current==base_sha,'ArdaPlatform remote changed since Mac prepared bundle')
        manifest_current=remote_branch(manifest_url)
        with tempfile.TemporaryDirectory(prefix='arda-cli-mac-publish-') as td:
            gitdir=Path(td)/'source';manifest=Path(td)/'manifest'
            cmd('gh','repo','clone',src,str(gitdir),'--','--quiet',timeout=240)
            require(git(gitdir,'rev-parse','HEAD')==base_sha,'ArdaPlatform clone main not at expected base')
            require(same_remote(git(gitdir,'remote','get-url','origin'),source_url),'ArdaPlatform origin mismatch')
            require(not git_status(gitdir),'ArdaPlatform clone dirty')
            if source_head!=base_sha:
                cmd('git','bundle','verify',str(bundle),cwd=gitdir,timeout=60)
                cmd('git','fetch','--no-tags',str(bundle),'HEAD',cwd=gitdir,timeout=150)
                fetched=git(gitdir,'rev-parse','FETCH_HEAD')
            else:
                fetched=base_sha
            require(fetched==source_head,'Received Mac Git bundle HEAD mismatch')
            require(cmd('git','merge-base','--is-ancestor',base_sha,source_head,cwd=gitdir,check=False,output=True).returncode==0,
                    'Mac commit does not descend from current GitHub main')
            if source_head!=base_sha:
                cmd('git','checkout','--quiet','--detach',source_head,cwd=gitdir)
            scanned=scan_unpublished_history(gitdir,base_sha)
            say('Unpublished ArdaPlatform Git blobs screened: '+str(scanned))
            cmd('gh','repo','clone',MANIFEST_REPO,str(manifest),'--','--quiet',timeout=240)
            require(git(manifest,'rev-parse','HEAD')==manifest_current,'Manifest changed since preflight')
            require(same_remote(git(manifest,'remote','get-url','origin'),manifest_url),'Manifest origin mismatch')
            require(not git_status(manifest),'Manifest checkout dirty')
            parent=latest_release(manifest)
            files=existing_release(manifest,parent)
            data=json.loads(files['metadata/source-pins.json'])
            require(data.get('mac_ardaplatform',{}).get('repo') in ('Deadknight/ArdaPlatform',src),
                    'Manifest ArdaPlatform ownership mismatch')
            pin=data['mac_ardaplatform'].get('sha')
            require(isinstance(pin,str) and SHA.fullmatch(pin),'Manifest Mac pin invalid')
            require(cmd('git','merge-base','--is-ancestor',pin,source_head,cwd=gitdir,check=False,output=True).returncode==0,
                    'Mac commit does not descend from last checkpoint')
            if pin==source_head:
                return {'status':'NO_NEW_SOURCE_CHANGES','module':module,'git_head':source_head,
                        'latest_manifest_release':parent,'new_manifest':None}
            # Allow resume when source push succeeded but manifest push failed.
            require(remote_branch(source_url)==base_sha and remote_branch(manifest_url)==manifest_current,
                    'GitHub source or manifest changed during preflight')
            version=dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%d')+'-cli-v1.8-ardaplatform-'+source_head[:10]
            release=manifest_release(None,module,TARGETS[module],source_head,None,None,version,manifest)
            require(not (manifest/'releases'/version).exists(),'Release already exists')
            if source_head!=base_sha:
                git(gitdir,'push','origin',source_head+':refs/heads/main',timeout=480)
                require(remote_branch(source_url)==source_head,'ArdaPlatform remote push SHA mismatch')
                say('SOURCE_PUSH_VERIFIED='+source_head)
            # No rollback after this point if manifest upload fails.
            manifest_sha=publish_manifest(release,version,manifest)
            say('MANIFEST_PUSH_VERIFIED='+manifest_sha)
            return {'status':'PASS_PUBLISHED','module':module,'source_head':source_head,
                    'source_strategy':'DIRECT','source_remote_sha':source_head,
                    'manifest_release':version,'manifest_sha':manifest_sha,
                    'source_only_not_build_attested':True,'repo_sync':False,'build':False,'reboot':False}

if __name__=='__main__':
    try:
        inp=json.loads(base64.urlsafe_b64decode(sys.argv[1]).decode('utf-8'))
        result=run_publish_mac(inp) if inp.get('module')=='ArdaPlatform' else run_publish(inp)
        print('ARDA_PERSIST_RESULT_JSON='+json.dumps(result,sort_keys=True),flush=True)
    except Exception as e:
        # Information in exceptions is tightly controlled; do not include raw git/PEM content.
        print('ARDA_PERSIST_STOP='+str(e)[:450],flush=True)
        sys.exit(3)
