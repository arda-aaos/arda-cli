#!/usr/bin/env python3
"""Ephemeral Ubuntu source-apply transaction; never performs Git, builds, or deploy.

Loaded over SSH stdin by ARDA CLI. A read-only preflight and per-file CAS prevent
writing on top of unexpected Ubuntu modifications. Source changes are backed up.
"""
from __future__ import annotations
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile

SOURCE = 'packages/apps/Car/Cluster'
ALLOWED_DIRS = {'.git', '.repo', '.arda-backups', 'out', 'build', '.gradle', 'signing', '__pycache__', '.idea', '.vscode'}
IGNORED_NAMES = {'.DS_Store', '.env'}
IGNORED_SUFFIXES = {'.pk8', '.pem', '.key', '.jks', '.keystore', '.p12', '.pfx', '.mobileprovision', '.pyc'}
MAX_BYTES = 50 * 1024 * 1024
PRIVATE_KEY_MARKERS = (b'-----BEGIN PRIVATE KEY-----', b'-----BEGIN RSA PRIVATE KEY-----',
                       b'-----BEGIN EC PRIVATE KEY-----', b'-----BEGIN OPENSSH PRIVATE KEY-----',
                       b'-----BEGIN ENCRYPTED PRIVATE KEY-----')
STAGE_PATTERN = re.compile(r'/tmp/arda-cli-build\.[a-f0-9]{16}\.[A-Za-z0-9]{8}\Z')
SHA = re.compile(r'[0-9a-f]{64}\Z')
GIT_SHA = re.compile(r'[0-9a-f]{40}\Z')


def acceptable(rel: str) -> bool:
    if not isinstance(rel, str) or not rel or '\\' in rel or '\x00' in rel or rel.startswith('/'):
        return False
    parts = rel.split('/')
    if any(part in ('', '.', '..') for part in parts):
        return False
    p = PurePosixPath(rel)
    return (not p.is_absolute() and not any(v in ALLOWED_DIRS for v in parts[:-1])
            and p.name not in IGNORED_NAMES and p.suffix.lower() not in IGNORED_SUFFIXES)


def source_snapshot(root: Path) -> dict:
    result = {}
    for base, dirs, files in os.walk(root, followlinks=False):
        current = Path(base)
        for d in list(dirs):
            p = current / d
            rel = p.relative_to(root).as_posix()
            if d in ALLOWED_DIRS:
                dirs.remove(d)
            elif p.is_symlink():
                result[rel] = 'SYMLINK:' + os.readlink(p)
                dirs.remove(d)
        for f in files:
            p = current / f
            rel = p.relative_to(root).as_posix()
            if not acceptable(rel):
                continue
            if p.is_symlink():
                result[rel] = 'SYMLINK:' + os.readlink(p)
            elif p.is_file():
                h = hashlib.sha256()
                with p.open('rb') as handle:
                    for chunk in iter(lambda: handle.read(1024 * 1024), b''):
                        h.update(chunk)
                result[rel] = h.hexdigest()
    return dict(sorted(result.items()))


def root_source(root_raw: str) -> Path:
    root = Path(root_raw)
    if not root.is_absolute() or '..' in root.parts or not root.is_dir():
        raise RuntimeError('Invalid AOSP root')
    source = root / SOURCE
    if source.is_symlink() or not source.is_dir() or not source.resolve().is_relative_to(root.resolve()):
        raise RuntimeError('Unexpected Cluster source path')
    return source


def verify_path(source: Path, rel: str):
    if not acceptable(rel):
        raise RuntimeError('Unsafe source path in transaction')
    target = source / rel
    ancestor = source
    for segment in PurePosixPath(rel).parts[:-1]:
        ancestor = ancestor / segment
        if ancestor.is_symlink() or (ancestor.exists() and not ancestor.is_dir()):
            raise RuntimeError('Source path traverses symlink/non-directory')
    if target.is_symlink() or (target.exists() and not target.is_file()):
        raise RuntimeError('Target is not a regular source file')
    return target


def current_head(source: Path) -> str:
    p = subprocess.run(['git', '-C', str(source), 'rev-parse', 'HEAD'], capture_output=True, text=True, timeout=20)
    if p.returncode != 0 or not GIT_SHA.fullmatch(p.stdout.strip()):
        raise RuntimeError('Cannot verify Git source HEAD')
    return p.stdout.strip()


def read_payload(path: Path):
    if path.stat().st_size > MAX_BYTES:
        raise RuntimeError('Upload exceeds safe limit')
    with tarfile.open(path, 'r') as tar:
        members = tar.getmembers()
        if not members or len(members) > 2000:
            raise RuntimeError('Unexpected tar member count')
        names = [member.name for member in members]
        if len(names) != len(set(names)) or names[0] != 'manifest.json':
            raise RuntimeError('Duplicate or missing manifest')
        for member in members:
            if not member.isfile() or member.size < 0 or member.size > MAX_BYTES:
                raise RuntimeError('Non-regular archive member')
            if member.name != 'manifest.json':
                if not member.name.startswith('files/') or not acceptable(member.name[6:]):
                    raise RuntimeError('Unsafe archive path')
        manifest = json.load(tar.extractfile(members[0]))
        if manifest.get('schema') != 1 or manifest.get('source') != SOURCE:
            raise RuntimeError('Invalid archive manifest')
        baseline = manifest.get('baseline')
        changed = manifest.get('changed')
        if (not isinstance(baseline, dict) or not isinstance(changed, dict) or not changed):
            raise RuntimeError('Invalid baseline/changes')
        if (any(not acceptable(k) or not isinstance(v, str) or
                not (SHA.fullmatch(v) or v.startswith('SYMLINK:')) for k,v in baseline.items())
                or any(not acceptable(k) or not isinstance(v,str) or not SHA.fullmatch(v) for k,v in changed.items())):
            raise RuntimeError('Invalid source hashes')
        if set(names[1:]) != {'files/' + n for n in changed}:
            raise RuntimeError('Archive payload does not match approved changed paths')
        content = {}
        total = 0
        for member in members[1:]:
            data = tar.extractfile(member).read()
            total += len(data)
            if total > MAX_BYTES:
                raise RuntimeError('Excessive source transfer')
            rel = member.name[6:]
            if hashlib.sha256(data).hexdigest() != changed[rel]:
                raise RuntimeError('Staged source changed or SHA mismatch')
            if any(marker in data for marker in PRIVATE_KEY_MARKERS):
                raise RuntimeError('Private-key marker detected; guarded sync stopped')
            content[rel] = (data, member.mode & 0o777)
        return manifest, content


def apply(root: Path, stage: Path):
    source = root_source(str(root))
    manifest, incoming = read_payload(stage / 'changes.tar')
    if not GIT_SHA.fullmatch(str(manifest.get('expected_head', ''))):
        raise RuntimeError('Invalid source HEAD')
    if current_head(source) != manifest['expected_head']:
        raise RuntimeError('Ubuntu Git HEAD moved; no files overwritten')
    baseline = manifest['baseline']
    if source_snapshot(source) != baseline:
        raise RuntimeError('Ubuntu sources differ from tracked baseline; no files overwritten')
    # Pre-check paths and existence before any mutation.
    for rel in incoming:
        verify_path(source, rel)
    root_backups = Path.home() / '.local/share/arda-cli/backups'
    root_backups.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(root_backups, 0o700)
    backup = Path(tempfile.mkdtemp(prefix='cluster-', dir=root_backups))
    os.chmod(backup, 0o700)
    changed_targets = []
    created_directories = []
    try:
        for rel in sorted(incoming):
            target = verify_path(source, rel)
            data, mode = incoming[rel]
            previous = target.is_file()
            if previous:
                h = hashlib.sha256()
                with target.open('rb') as existing:
                    for chunk in iter(lambda: existing.read(1024*1024), b''):
                        h.update(chunk)
                if h.hexdigest() != baseline.get(rel):
                    raise RuntimeError('Source target changed during transfer; rolling back')
                older = backup / rel
                older.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(target, older)
            # Source dirs are created only inside verified checkout.
            missing = []
            ancestor = target.parent
            while not ancestor.exists() and ancestor != source:
                missing.append(ancestor)
                ancestor = ancestor.parent
            for item in reversed(missing):
                item.mkdir(mode=0o755)
                created_directories.append(item)
            fd, temp = tempfile.mkstemp(prefix='.arda-write-', dir=target.parent)
            try:
                with os.fdopen(fd, 'wb') as dest:
                    dest.write(data)
                    dest.flush()
                    os.fsync(dest.fileno())
                os.chmod(temp, (target.stat().st_mode & 0o777) if previous else (mode & 0o755))
                os.replace(temp, target)
            finally:
                if os.path.lexists(temp): os.unlink(temp)
            changed_targets.append((rel, previous))
        expected = dict(baseline)
        expected.update(manifest['changed'])
        if source_snapshot(source) != dict(sorted(expected.items())):
            raise RuntimeError('Post-transfer full source checksum verification failed')
        if current_head(source) != manifest['expected_head']:
            raise RuntimeError('Git HEAD unexpectedly moved during transfer')
        (backup / 'transfer.json').write_text(json.dumps({
            'changed': sorted(incoming), 'new': sorted(k for k in incoming if k not in baseline),
            'created_utc': datetime.now(timezone.utc).isoformat(),
            'source': str(source), 'head': manifest['expected_head'],
        }, indent=2))
        return {'ok': True, 'applied': len(incoming), 'backup': str(backup),
                'head': manifest['expected_head']}
    except Exception:
        errors=[]
        for rel, previous in reversed(changed_targets):
            try:
                dest = verify_path(source, rel)
                if previous:
                    shutil.copy2(backup / rel, dest)
                else:
                    dest.unlink(missing_ok=True)
            except Exception as exc:
                errors.append(str(exc))
        for p in reversed(created_directories):
            try: p.rmdir()
            except OSError: pass
        if errors:
            raise RuntimeError('ROLLBACK_PARTIAL; inspect backup at ' + str(backup))
        raise


def main():
    payload = json.loads(base64.urlsafe_b64decode(sys.argv[1]))
    action = payload.get('action')
    stage = Path(payload.get('stage', ''))
    if not STAGE_PATTERN.fullmatch(str(stage)) or stage.is_symlink():
        raise RuntimeError('Invalid staging path')
    if stage.exists() and stage.stat().st_uid != os.getuid():
        raise RuntimeError('Staging dir not owned by current user')
    if action == 'cleanup':
        if stage.is_dir(): shutil.rmtree(stage)
        print(json.dumps({'ok':True,'cleaned':True}))
        return
    if action != 'apply' or not stage.is_dir():
        raise RuntimeError('Invalid action or stage')
    print(json.dumps(apply(Path(payload['root']), stage), sort_keys=True))

if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(json.dumps({'ok':False, 'error':str(exc)[:500]}))
        sys.exit(1)
