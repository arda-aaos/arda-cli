#!/usr/bin/env python3
"""Ephemeral read-only Ubuntu helper. Executed via SSH stdin, not installed remotely.
Payload is base64-encoded JSON containing action, AOSP root and validated inputs.
Emits exactly one JSON result to stdout. Never calls repo sync or builds anything.
"""
from __future__ import annotations
import base64
import json
import os
from pathlib import Path
import subprocess
import sys


def cmd(args, cwd=None, timeout=22):
    try:
        p = subprocess.run(args, cwd=cwd, stdin=subprocess.DEVNULL,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           text=True, timeout=timeout, errors='replace')
        return {'rc': p.returncode, 'out': p.stdout.strip(), 'err': p.stderr[-300:].strip()}
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return {'rc': 125, 'out': '', 'err': str(exc)[:300]}


def valid_root(raw):
    root = Path(raw)
    if not root.is_absolute() or '..' in root.parts:
        raise ValueError('Invalid root')
    return root


def safe_path(root, raw):
    relative = Path(raw)
    if relative.is_absolute() or '..' in relative.parts or str(relative) in ('', '.'):
        raise ValueError('Unsafe source path')
    path = root / relative
    if not path.resolve().is_relative_to(root.resolve()):
        raise ValueError('Source path escapes AOSP tree')
    return path


def module_inventory(root, product=None):
    # Prefer a product-specific merged index over a Soong-only index, then
    # choose the most recently generated product inventory if several exist.
    products = root / 'out/target/product'
    if product:
        if not isinstance(product, str) or not product.replace('_','').replace('-','').isalnum():
            raise ValueError('Invalid product directory')
        target = products / product / 'module-info.json'
        return target if target.is_file() else None
    if products.exists():
        indexed = [p for p in products.glob('*/module-info.json') if p.is_file()]
        if indexed:
            return max(indexed, key=lambda p: (p.stat().st_mtime, str(p)))
    return next((p for p in (root / 'out/soong/module-info.json',
                             root / 'out/module-info.json') if p.is_file()), None)


def module_rows(root, names, search, limit, offset=0, product=None):
    f = module_inventory(root, product)
    if f is None:
        return {'available': False, 'path': None, 'total': 0, 'matches': 0,
                'rows': [], 'warning': 'module-info.json absent. No build was triggered.'}
    with f.open('r', encoding='utf-8') as file:
        data = json.load(file)
    if not isinstance(data, dict):
        raise ValueError('Invalid module-info format')
    rows = []
    matches = 0
    for name in sorted(data):
        if names and name not in names:
            continue
        entry = data[name]
        if not isinstance(entry, dict):
            continue
        paths = entry.get('path', [])
        classes = entry.get('class', [])
        paths = paths if isinstance(paths, list) else []
        classes = classes if isinstance(classes, list) else []
        if search and search.casefold() not in (name + ' ' + ' '.join(map(str, paths))).casefold():
            continue
        matches += 1
        if matches > offset and (limit is None or len(rows) < limit):
            rows.append({'name': name, 'path': paths if limit is None else paths[:3],
                         'class': classes if limit is None else classes[:3]})
    return {'available': True, 'path': str(f.relative_to(root)),
            'indexed_at_epoch': int(f.stat().st_mtime),
            'total': len(data), 'matches': matches, 'offset': offset, 'rows': rows}


def project_rows(root, search, limit, offset=0):
    # .repo/project.list is a read-only existing inventory, no repo tooling needed.
    file = root / '.repo/project.list'
    if not file.is_file():
        return {'available': False, 'rows': [], 'matches': 0,
                'warning': '.repo/project.list not found; no repo command run'}
    paths = sorted(set(line.strip() for line in file.read_text(errors='replace').splitlines()
                       if line.strip() and not line.startswith('#')))
    filt = [p for p in paths if not search or search.casefold() in p.casefold()]
    return {'available': True, 'matches': len(filt), 'total': len(paths),
            'offset': offset, 'rows': filt[offset:] if limit is None else filt[offset:offset + limit]}


def source_info(root, path_raw):
    path = safe_path(root, path_raw)
    if not path.is_dir():
        return {'exists': False, 'path': path_raw}
    git = cmd(['git', 'rev-parse', '--show-toplevel'], cwd=path)
    if git['rc'] != 0:
        return {'exists': True, 'path': path_raw, 'git': False}
    top = Path(git['out'])
    sha = cmd(['git', 'rev-parse', 'HEAD'], cwd=top)
    status = cmd(['git', 'status', '--porcelain=v1', '-uall'], cwd=top, timeout=40)
    # Do not expose contents or secrets, just count changes. .arda-backups may be untracked.
    lines = status['out'].splitlines() if status['rc'] == 0 else []
    return {'exists': True, 'path': path_raw, 'git': True,
            'git_root': str(top), 'head': sha['out'] if sha['rc'] == 0 else None,
            'changed_files': len(lines) if status['rc'] == 0 else None,
            'status_ok': status['rc'] == 0}


def apk_artifact(root, product):
    """Read-only SHA of the signed installed Cluster APK in the selected product."""
    import hashlib
    if not isinstance(product, str) or not product.replace('_', '').replace('-', '').isalnum():
        raise ValueError('Invalid product for artifact lookup')
    base = root / 'out/target/product' / product
    paths = [base / partition / typ / 'DirectRenderingCluster/DirectRenderingCluster.apk'
             for partition in ('system', 'system_ext', 'product', 'vendor')
             for typ in ('priv-app', 'app')]
    for p in paths:
        if p.is_file() and not p.is_symlink() and p.resolve().is_relative_to(base.resolve()):
            h = hashlib.sha256()
            with p.open('rb') as fp:
                for chunk in iter(lambda: fp.read(1024*1024), b''):
                    h.update(chunk)
            return {'available':True, 'path':str(p.relative_to(root)),
                    'sha256':h.hexdigest(), 'size':p.stat().st_size}
    return {'available':False, 'warning':'Signed Cluster APK not found in expected product output'}


def doctor(root, paths, product=None):
    checks = {'aosp_root': root.is_dir(),
              'repo_metadata': (root / '.repo').is_dir(),
              'python3': True, 'git': cmd(['git', '--version'])['rc'] == 0,
              'rsync': cmd(['rsync', '--version'])['rc'] == 0,
              'module_inventory': module_inventory(root, product) is not None}
    sources = {p: safe_path(root, p).is_dir() for p in paths}
    return {'checks': checks, 'sources': sources}


# ---- v0.3 Git source strategy audit (read-only) ----
import re
from functools import lru_cache
import xml.etree.ElementTree as ET
from urllib.parse import urlsplit


def git_read(top, *arguments, timeout=28):
    """Git read operations with optional index locking disabled; no fetch."""
    env = dict(os.environ, GIT_OPTIONAL_LOCKS='0', GIT_TERMINAL_PROMPT='0')
    try:
        p = subprocess.run(['git', '-c', 'core.fsmonitor=false', '-c', 'core.untrackedCache=false', '-C', str(top), *arguments], input=None,
                           stdin=subprocess.DEVNULL, capture_output=True,
                           encoding='utf-8', errors='replace', timeout=timeout,
                           env=env)
        return p.returncode, p.stdout.strip(), p.stderr[-200:].strip()
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return 125, '', str(exc)[:200]


def clean_remote_url(url):
    """Remove URL userinfo/query/fragment, including Git remote passwords."""
    url = url.strip()
    # scp-like: [user@]host:path; no need to surface usernames
    if '://' not in url:
        if ':' in url and not url.startswith('/'):
            host, path = url.split(':', 1)
            host = host.rsplit('@', 1)[-1]
            if not re.fullmatch(r'[A-Za-z0-9.-]+', host):
                return '(nonstandard remote)'
            return f'{host}:{path.split("?", 1)[0].split("#", 1)[0]}'
        return '(local/unknown remote)'
    u = urlsplit(url)
    if not u.hostname or u.scheme not in ('https', 'http', 'ssh', 'git'):
        return '(nonstandard remote)'
    host = u.hostname.lower()
    try:
        port = f':{u.port}' if u.port else ''
    except ValueError:
        return '(malformed remote)'
    return f'{u.scheme}://{host}{port}{u.path}'


def remote_owner(url):
    url = url.casefold()
    if 'github.com' in url:
        if re.search(r'(?:[/:])deadknight(?:/|$)', url):
            return 'Deadknight'
        return 'github-third-party'
    if 'android.googlesource.com' in url:
        return 'AOSP'
    if 'raspberry-vanilla' in url:
        return 'raspberry-vanilla'
    if url.startswith('(local'):
        return 'local'
    return 'unknown'


def git_remotes(top):
    rc, out, _ = git_read(top, 'config', '--get-regexp', r'^remote\..*\.url$')
    rows = []
    if rc == 0:
        for line in out.splitlines():
            key, sep, url = line.partition(' ')
            if not sep:
                continue
            name = key[len('remote.'):-len('.url')]
            redacted = clean_remote_url(url)
            rows.append({'name': name, 'url': redacted, 'owner': remote_owner(redacted)})
    return rows


@lru_cache(maxsize=4)
def active_manifest_projects(root):
    """Best-effort LOCAL manifest overlays, no network/repo executable.

    Absence or unsupported extensions are surfaced as warnings, never certified.
    """
    repo = root / '.repo'
    primary = repo / 'manifest.xml'
    if not primary.is_file():
        return {}, {}, ['active .repo/manifest.xml not available']
    remotes, projects, warnings = {}, {}, []
    defaults = {'remote': '', 'revision': ''}
    visiting = set()

    def parse(file, depth=0):
        if depth > 12:
            warnings.append('manifest include depth exceeded')
            return
        real = file.resolve()
        if not real.is_relative_to(repo.resolve()) or not real.is_file():
            warnings.append('manifest include absent/escapes .repo')
            return
        if real in visiting:
            warnings.append('manifest include cycle')
            return
        visiting.add(real)
        try:
            tree = ET.parse(real)
            if tree.getroot().tag != 'manifest':
                warnings.append('unexpected manifest root')
                return
            for element in tree.getroot():
                tag = element.tag
                if tag == 'include':
                    target = element.get('name', '')
                    # Reject arbitrary absolute/parent paths.
                    if not target or Path(target).is_absolute() or '..' in Path(target).parts:
                        warnings.append('unsafe manifest include ignored')
                    else:
                        candidate = (real.parent / target)
                        if not candidate.is_file():
                            candidate = repo / 'manifests' / target
                        parse(candidate, depth + 1)
                elif tag == 'remote':
                    name = element.get('name')
                    if name: remotes[name] = element.get('fetch', '')
                elif tag == 'default':
                    defaults.update({k: v for k in ('remote', 'revision')
                                     if (v := element.get(k)) is not None})
                elif tag == 'project':
                    name = element.get('name', '')
                    path = element.get('path', name)
                    if path and not Path(path).is_absolute() and '..' not in Path(path).parts:
                        projects[path] = {'name': name, 'remote': element.get('remote') or defaults['remote'],
                                          'revision': element.get('revision') or defaults['revision'],
                                          'source': str(real.relative_to(repo.resolve())),
                                          'path': path}
                elif tag == 'remove-project':
                    name, path = element.get('name'), element.get('path')
                    for key, value in list(projects.items()):
                        if (name and value.get('name') == name) or (path and key == path):
                            projects.pop(key, None)
                elif tag == 'extend-project':
                    name, path = element.get('name'), element.get('path')
                    for key, value in projects.items():
                        if (not path or key == path) and (not name or value.get('name') == name):
                            for k in ('revision', 'remote'):
                                if element.get(k): value[k] = element.get(k)
                elif tag == 'submanifest':
                    warnings.append('submanifest entries not resolved')
        except (OSError, ET.ParseError) as exc:
            warnings.append('manifest XML parse failed: ' + type(exc).__name__)
        finally:
            visiting.remove(real)

    parse(primary)
    locals_ = repo / 'local_manifests'
    if locals_.is_dir():
        for file in sorted(locals_.glob('*.xml')):
            parse(file)
    return projects, remotes, warnings


def diff_metrics(top, base, head):
    result = {'base': base, 'available': False, 'ancestry': 'unknown'}
    if not re.fullmatch('[0-9a-fA-F]{40}', base):
        result['error'] = 'base must be full 40-hex commit'
        return result
    rc, _, _ = git_read(top, 'cat-file', '-e', base + '^{commit}')
    if rc != 0:
        result['error'] = 'base object unavailable locally; no fetch attempted'
        return result
    result['available'] = True
    rc, _, _ = git_read(top, 'merge-base', '--is-ancestor', base, head)
    if rc != 0:
        result['ancestry'] = 'not_ancestor'
        result['error'] = 'base is not an ancestor of HEAD; no patch recommendation'
        return result
    result['ancestry'] = 'ancestor'
    rc, out, err = git_read(top, 'diff', '--no-ext-diff', '--no-textconv', '--no-renames',
                            '--numstat', base, head, timeout=55)
    if rc != 0:
        result['error'] = 'git diff unavailable: ' + err
        return result
    files, added, removed, binary = 0, 0, 0, 0
    for line in out.splitlines():
        parts = line.split('\t', 2)
        if len(parts) != 3: continue
        files += 1
        if parts[0] == '-' or parts[1] == '-':
            binary += 1
        else:
            added += int(parts[0]); removed += int(parts[1])
    result.update(files=files, lines_added=added, lines_deleted=removed,
                  binary_files=binary, measured=True)
    return result


def strategy_inspect(root, source, base=None):
    path = safe_path(root, source)
    if not path.is_dir():
        return {'source': source, 'exists': False}
    rc, top_raw, _ = git_read(path, 'rev-parse', '--show-toplevel')
    if rc != 0:
        return {'source': source, 'exists': True, 'git': False}
    top = Path(top_raw).resolve()
    if not top.is_relative_to(root.resolve()):
        raise ValueError('Git worktree escapes AOSP root')
    repo_path = str(top.relative_to(root.resolve()))
    rc, sha, _ = git_read(top, 'rev-parse', 'HEAD')
    if rc or not re.fullmatch('[0-9a-f]{40}', sha):
        return {'source': source, 'exists': True, 'git': True, 'error': 'Git HEAD unavailable'}
    rc, state, _ = git_read(top, 'status', '--porcelain=v1', '-uall', timeout=40)
    changed = len(state.splitlines()) if rc == 0 else None
    rc, isshallow, _ = git_read(top, 'rev-parse', '--is-shallow-repository')
    local_manifests, manifest_remotes, notes = active_manifest_projects(root)
    manifest = local_manifests.get(repo_path)
    if manifest:
        manifest = manifest.copy()
        fetch = manifest_remotes.get(manifest.get('remote', ''), '')
        manifest['fetch'] = clean_remote_url(fetch) if fetch else ''
        manifest['owner'] = remote_owner(manifest['fetch']) if fetch else 'unknown'
    remotes = git_remotes(top)
    data = {'source': source, 'repo_path': repo_path, 'exists': True, 'git': True,
            'head': sha, 'dirty_files': changed, 'shallow': isshallow == 'true' if rc == 0 else None,
            'remotes': remotes, 'manifest': manifest, 'manifest_warnings': notes[:8]}
    if base:
        data['base_diff'] = diff_metrics(top, base, sha)
    return data


def persist_status(root, source, base=None):
    """Read-only Git working-tree inspection; never disclose file/key contents."""
    import re
    inspected = strategy_inspect(root, source, base)
    if not inspected.get('git'):
        return inspected
    path = safe_path(root, source)
    rc, top_str, _ = git_read(path, 'rev-parse', '--show-toplevel')
    if rc:
        raise ValueError('Git project root unknown')
    top = Path(top_str).resolve()
    env = dict(os.environ, GIT_OPTIONAL_LOCKS='0', GIT_TERMINAL_PROMPT='0')
    p = subprocess.run(['git', '-c', 'core.fsmonitor=false', '-C', str(top), 'status',
                        '--porcelain=v1', '-z', '--untracked-files=all'],
                       stdin=subprocess.DEVNULL, capture_output=True, timeout=75, env=env)
    if p.returncode:
        raise ValueError('Git porcelain status failed')
    raw = p.stdout.decode('utf-8', errors='replace')
    if raw and not raw.endswith('\0'):
        raise ValueError('Incomplete porcelain status')
    entries = raw[:-1].split('\0') if raw else []
    result = {'source': 0, 'backup_or_output': 0, 'sensitive_path': 0,
              'staged': 0, 'untracked': 0, 'total': 0, 'examples': []}
    sensitive = ('.pk8', '.jks', '.keystore', '.p12', '.pfx', '.key', '.gpg', '.kdbx')
    i = 0
    while i < len(entries):
        row = entries[i]
        if len(row) < 4 or row[2] != ' ':
            raise ValueError('Unexpected Git porcelain format')
        code, name = row[:2], row[3:]
        if not name or name.startswith('/') or '..' in Path(name).parts:
            raise ValueError('Unsafe Git filename')
        if any(c in code for c in 'RC'):
            i += 1
            if i >= len(entries):
                raise ValueError('Incomplete Git rename/copy')
        parts = set(Path(name).parts)
        if code == '??' and name.startswith('updater/signing/'):
            # Existing local signing files are never staged by ARDA.
            result['backup_or_output'] += 1
        elif ('signing' in parts or name.lower().endswith(sensitive) or
                re.search(r'(?:^|[/_.-])(?:private[_-]?key|release[_-]?key|signing[_-]?key|keystore)(?:$|[/_.-])', name, re.I)):
            result['sensitive_path'] += 1
        elif parts & {'.arda-backups', 'build', 'out', '.repo', '.git'} or name.endswith(('~', '.bak', '.orig', '.swp')):
            result['backup_or_output'] += 1
        else:
            result['source'] += 1
            if len(result['examples']) < 6:
                result['examples'].append({'status': code, 'path': name})
        result['staged'] += int(code[0] not in (' ', '?'))
        result['untracked'] += int(code == '??')
        result['total'] += 1
        i += 1
    inspected['source_status'] = result
    return inspected



# V1.6 read-only GitHub provenance / clean patch replay.
# Can create TEMPORARY dirs outside the AOSP tree. Never writes to source,
# .repo, manifests, device, remote branches, or GH.
import base64 as _b64
import hashlib as _hashlib
import tempfile as _tempfile

PINNED_MANIFEST = 'a85ead3d1d0973e73d7ff34a0cd2d1d67f1ceb0f'
MANIFEST_REPO = 'arda-aaos/arda-aaos-manifest'
RELEASE_DIR = 'releases/2026-11-16-v49.7'
# Read-only audit may resolve a V49.7 historical alias; publishing only uses the org.
ALLOW_REPOS = {'Deadknight/ArdaPlatform','Deadknight/android_vendor_arda_ardaplatform',
               'Deadknight/arda-aaos-manifest','arda-aaos/ArdaPlatform',
               'arda-aaos/android_vendor_arda_ardaplatform','arda-aaos/arda-aaos-manifest'}


def _gh_api(endpoint, *, maximum=4*1024*1024):
    """Only GET GitHub API; never include credentials in output."""
    env = dict(os.environ, GH_PROMPT_DISABLED='1', GIT_TERMINAL_PROMPT='0')
    try:
        res = subprocess.run(['gh','api','--method','GET',endpoint], stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=42, env=env)
    except (OSError, subprocess.TimeoutExpired):
        return None, 'github_api_unavailable'
    if res.returncode or len(res.stdout)>maximum:
        return None, 'github_api_failed_or_oversized'
    try:
        return json.loads(res.stdout), None
    except ValueError:
        return None, 'github_api_invalid_json'


def _gh_content(path):
    obj,err=_gh_api(f'repos/{MANIFEST_REPO}/contents/{path}?ref={PINNED_MANIFEST}')
    if err:return None,err
    if not isinstance(obj,dict) or obj.get('encoding')!='base64':
        return None, 'github_content_not_base64'
    try:
        raw=_b64.b64decode(obj['content'], validate=False)
        if len(raw)>2*1024*1024: return None,'github_content_too_large'
        return raw,None
    except (KeyError,ValueError):
        return None,'github_content_decode_failed'


def verify_github_pin(repository,sha):
    if repository not in ALLOW_REPOS or not re.fullmatch('[0-9a-f]{40}',sha or ''):
        raise ValueError('Unrecognized GitHub pin target')
    obj,err=_gh_api(f'repos/{repository}/git/commits/{sha}')
    if err:return {'verified':False,'reason':err,'repo':repository,'sha':sha}
    value=obj.get('sha') if isinstance(obj,dict) else None
    return {'verified':value==sha,'reason':'found_exact_commit' if value==sha else 'github_sha_mismatch',
            'repo':repository,'sha':sha}


def _git_quiet(args, cwd, timeout=70, input_bytes=None):
    env=dict(os.environ,GIT_OPTIONAL_LOCKS='0',GIT_TERMINAL_PROMPT='0')
    try:
        result=subprocess.run(['git', *args],cwd=cwd,
            **({'input':input_bytes} if input_bytes is not None else {'stdin':subprocess.DEVNULL}),stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,timeout=timeout)
        return result.returncode,result.stdout.strip()
    except (OSError,subprocess.TimeoutExpired):
        return 125,b''


def replay_clean_patch(repo,base,patch,expected_tree):
    """Clone local repo into disposable directory, checkout base, apply trusted pinned patch.
    No `git worktree` and no modification of the shared source checkout.
    """
    if not re.fullmatch('[0-9a-f]{40}',base) or not re.fullmatch('[0-9a-f]{40}',expected_tree):
        return False,'invalid_base_or_tree_sha'
    if len(patch)>2*1024*1024:
        return False,'patch_exceeds_audit_limit'
    rc,_=_git_quiet(['-C',str(repo),'cat-file','-e',base+'^{commit}'],repo)
    if rc:return False,'upstream_base_object_missing'
    with _tempfile.TemporaryDirectory(prefix='arda-cluster-audit-') as tmp:
        target=Path(tmp)/'clone'
        rc,_=_git_quiet(['clone','--quiet','--shared','--no-checkout','--',str(repo),str(target)],tmp,timeout=85)
        if rc:return False,'temporary_clone_failed'
        rc,_=_git_quiet(['checkout','--quiet','--detach',base],target,timeout=70)
        if rc:return False,'temporary_base_checkout_failed'
        rc,_=_git_quiet(['apply','--binary','--index','-'],target,timeout=70,input_bytes=patch)
        if rc:return False,'clean_patch_application_failed'
        rc,out=_git_quiet(['write-tree'],target)
        if rc:return False,'replay_tree_read_failed'
        return out.decode('ascii','replace')==expected_tree, 'tree_equal' if out.decode('ascii','replace')==expected_tree else 'replay_tree_mismatch'


def release_audit(root,source,record):
    """Audit V49.7 PATCH source only; key-history audit is explicitly NOT attested."""
    if not isinstance(record,dict) or source!='packages/apps/Car/Cluster':
        raise ValueError('V1.6 clean replay is enabled only for DirectRenderingCluster')
    if record.get('baseline')!='7244742c0268e1a1f6e88f5b2e1df0c0ec2c825a' or record.get('release_head')!='381ec76af237a746c48c9b1efa62d58f7b9b246e':
        raise ValueError('Release record changed; not an audited V49.7 checkpoint')
    project=safe_path(root,source)
    if not project.is_dir():return {'verified':False,'reason':'project_missing'}
    rc,repo_raw,_=git_read(project,'rev-parse','--show-toplevel')
    if rc:return {'verified':False,'reason':'git_root_missing'}
    repo=Path(repo_raw).resolve()
    if repo != project.resolve() or not repo.is_relative_to(root.resolve()):
        return {'verified':False,'reason':'unexpected_git_root'}
    rc,head,_=git_read(repo,'rev-parse','HEAD')
    if rc or head!=record['release_head']:
        return {'verified':False,'reason':'local_head_differs_from_v49_7','head':head if not rc else ''}
    rc,status,_=git_read(repo,'status','--porcelain=v1','--untracked-files=all',timeout=45)
    # Ignore ONLY the known non-source ARDA backups. Other dirty paths block the audit.
    if rc or any(not line[3:].startswith('.arda-backups/') for line in status.splitlines() if len(line)>=4):
        return {'verified':False,'reason':'unexpected_dirty_checkout'}
    pinned=verify_github_pin(MANIFEST_REPO,PINNED_MANIFEST)
    if not pinned['verified']:return {'verified':False,'reason':'manifest_commit_unverified','manifest':pinned}
    raw,err=_gh_content(f'{RELEASE_DIR}/metadata/source-pins.json')
    if err:return {'verified':False,'reason':'metadata_unavailable:'+err}
    try:
        meta=json.loads(raw)
    except (ValueError,UnicodeDecodeError):return {'verified':False,'reason':'metadata_invalid'}
    item=meta.get('car_cluster',{})
    if item.get('base_sha')!=record['baseline'] or item.get('local_commit_sha')!=head:
        return {'verified':False,'reason':'checkpoint_metadata_sha_mismatch'}
    expected_tree=item.get('post_patch_tree','')
    if not re.fullmatch('[0-9a-f]{40}',expected_tree):
        return {'verified':False,'reason':'checkpoint_tree_missing'}
    rc,local_tree,_=git_read(repo,'rev-parse','HEAD^{tree}')
    if rc or local_tree!=expected_tree:
        return {'verified':False,'reason':'local_tree_different','local_tree':local_tree}
    patch,err=_gh_content(f'{RELEASE_DIR}/patches/cluster-v42.patch')
    if err:return {'verified':False,'reason':'patch_unavailable:'+err}
    digest=_hashlib.sha256(patch).hexdigest()
    if digest!=item.get('patch_sha256'):
        return {'verified':False,'reason':'remote_patch_sha256_mismatch'}
    okay,why=replay_clean_patch(repo,record['baseline'],patch,expected_tree)
    return {'verified':okay,'reason':why,'manifest_sha_verified':True,
            'patch_sha256_verified':True,'clean_replay_verified':okay,
            'local_tree_verified':True,'head':head,'tree':expected_tree,
            'secret_history_audited':False,'source_writes':False,'publish':False}


def carlauncher_fork_audit(root):
    """Only verifies the already-existing CarLauncher fork and its non-main branch."""
    source='packages/apps/Car/Launcher'
    inspected=strategy_inspect(root,source)
    if not inspected.get('git'):
        return {'verified':False,'reason':'source_git_not_available'}
    project=root/source
    head=inspected.get('head')
    expect='https://github.com/arda-aaos/arda-aaos-car-launcher'
    remotes=inspected.get('remotes') or {}
    urls=[]
    if isinstance(remotes,dict):
        for name,entry in remotes.items():
            if isinstance(entry,dict):urls += [entry.get('fetch',''),entry.get('push','')]
            elif isinstance(entry,str):urls.append(entry)
    elif isinstance(remotes,list):
        for entry in remotes:
            if isinstance(entry,dict):urls.extend([entry.get('url',''),entry.get('fetch','')])
    def accepted(s):
        if not isinstance(s,str):return False
        return s.rstrip('/').removesuffix('.git') in (expect,'git@github.com:arda-aaos/arda-aaos-car-launcher')
    owner_ok=any(accepted(u) for u in urls)
    manifest=inspected.get('manifest') or {}
    pin=manifest.get('revision')
    manifest_ok=(isinstance(pin,str) and pin==head and
                 manifest.get('name')=='android_packages_apps_Car_Launcher')
    git_state=cmd(['git','status','--porcelain=v1','--untracked-files=all'],cwd=project,timeout=40)
    clean=git_state['rc']==0 and not any(line and not line.startswith('?? .arda-backups/')
                                        for line in git_state['out'].splitlines())
    remote=cmd(['git','ls-remote','--heads',expect+'.git','refs/heads/arda-aaos16'],timeout=90)
    remote_sha=None
    if remote['rc']==0 and len(remote['out'].splitlines())==1:
        bits=remote['out'].split()
        if len(bits)==2 and re.fullmatch(r'[a-f0-9]{40}',bits[0]) and bits[1]=='refs/heads/arda-aaos16':
            remote_sha=bits[0]
    verified=(bool(owner_ok and manifest_ok and clean and remote_sha==head))
    return {'verified':verified,
            'reason':'matched_existing_fork_branch_manifest' if verified else 'fork_remote_or_manifest_pin_not_fully_verified',
            'local_head':head,'branch':'arda-aaos16','source':source,
            'remote_sha':remote_sha,'manifest_revision':pin,
            'remote_owner_verified':owner_ok,'local_manifest_verified':manifest_ok,
            'source_clean_except_backups':clean,'no_push':True}


def main():
    payload = json.loads(base64.urlsafe_b64decode(sys.argv[1]).decode('utf-8'))
    root = valid_root(payload['root'])
    action = payload['action']
    names = payload.get('names', [])
    product = payload.get('product')
    search = payload.get('search', '')
    limit = None if payload.get('full') is True else int(payload.get('limit', 100))
    offset = int(payload.get('offset', 0))
    if limit is not None and not 1 <= limit <= 1000:
        raise ValueError('limit must be 1..1000 (use --full to show all)')
    if offset < 0:
        raise ValueError('offset cannot be negative')
    if action == 'modules':
        result = module_rows(root, names, search, limit, offset, product)
    elif action == 'projects':
        result = project_rows(root, search, limit, offset)
    elif action == 'source':
        result = source_info(root, payload['source'])
    elif action == 'apk_artifact':
        result = apk_artifact(root, product)
    elif action == 'strategy':
        result = strategy_inspect(root, payload['source'], payload.get('base'))
    elif action == 'persist_plan':
        result = persist_status(root, payload['source'], payload.get('base'))
    elif action == 'persist_audit':
        result = release_audit(root, payload['source'], payload['record'])
    elif action == 'launcher_audit':
        result = carlauncher_fork_audit(root)
    elif action == 'verify_github_pin':
        result = verify_github_pin(payload['repository'], payload['sha'])
    elif action == 'strategy_batch':
        items = payload.get('items', [])
        if not isinstance(items, list) or len(items) > 100:
            raise ValueError('strategy_batch requires <=100 items')
        result = {'rows': [strategy_inspect(root, x['source'], x.get('base')) for x in items] }
    elif action == 'doctor':
        result = doctor(root, payload.get('paths', []), product)
    else:
        raise ValueError('Unknown action')
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(json.dumps({'error': str(exc)[:450]}))
        raise SystemExit(1)

