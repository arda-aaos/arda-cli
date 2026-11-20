"""First guarded AOSP module build workflow.

Only the confirmed DirectRenderingCluster is enabled.  Plans and tracking
never mutate Ubuntu source; --sync requires a recorded common baseline.
"""
from __future__ import annotations
import base64
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import shutil
import subprocess
import tarfile
import tempfile
import zipfile

from . import __version__
from .config import PROFILES, local_root, PACKAGE_ROOT

BUILD_ENABLED = {'DirectRenderingCluster': 'packages/apps/Car/Cluster/DirectRenderingCluster'}
IGNORED_DIRS = {'.git', '.repo', '.arda-backups', 'out', 'build', '.gradle', 'signing', '__pycache__', '.idea', '.vscode'}
IGNORED_NAMES = {'.DS_Store', '.env'}
IGNORED_SUFFIXES = {'.pk8', '.pem', '.key', '.jks', '.keystore', '.p12', '.pfx', '.mobileprovision', '.pyc'}
MAX_ARCHIVE_SIZE = 50 * 1024 * 1024
PRIVATE_KEY_MARKERS = (b'-----BEGIN PRIVATE KEY-----', b'-----BEGIN RSA PRIVATE KEY-----',
                       b'-----BEGIN EC PRIVATE KEY-----', b'-----BEGIN OPENSSH PRIVATE KEY-----',
                       b'-----BEGIN ENCRYPTED PRIVATE KEY-----')


def valid_relative(raw: str) -> bool:
    if not raw or '\\' in raw or '\x00' in raw or raw.startswith('/'):
        return False
    p = PurePosixPath(raw)
    if p.is_absolute() or any(x in ('..', '.') for x in raw.split('/')):
        return False
    if any(x in IGNORED_DIRS for x in p.parts[:-1]):
        return False
    if p.name in IGNORED_NAMES or p.suffix.lower() in IGNORED_SUFFIXES:
        return False
    return True


def snapshot(folder: Path) -> dict[str,str]:
    """Hash only synced source files, matching pull's exclusions."""
    if not folder.is_dir() or folder.is_symlink():
        raise ValueError(f'Not a real source directory: {folder}')
    result = {}
    for base, dirs, files in os.walk(folder, followlinks=False):
        current = Path(base)
        for d in list(dirs):
            p = current / d
            rel = p.relative_to(folder).as_posix()
            if d in IGNORED_DIRS:
                dirs.remove(d)
            elif p.is_symlink():
                result[rel] = 'SYMLINK:' + os.readlink(p)
                dirs.remove(d)
        for file in files:
            p = current / file
            rel = p.relative_to(folder).as_posix()
            if not valid_relative(rel):
                continue
            if p.is_symlink():
                result[rel] = 'SYMLINK:' + os.readlink(p)
            elif p.is_file():
                h = hashlib.sha256()
                with p.open('rb') as fd:
                    for chunk in iter(lambda: fd.read(1024*1024), b''):
                        h.update(chunk)
                result[rel] = h.hexdigest()
    return dict(sorted(result.items()))


def state_path(cfg: dict, name: str) -> Path:
    # Outside source; never mixed into Git checkouts.
    return Path.home() / '.local/share/arda-cli-v1/state' / (name + '.json')


def read_state(cfg: dict, name: str) -> dict | None:
    p = state_path(cfg, name)
    if not p.is_file():
        return None
    raw = json.loads(p.read_text('utf-8'))
    if raw.get('module') != name or raw.get('ubuntu') != cfg['ubuntu'] or raw.get('aosp_root') != cfg['aosp_root']:
        raise ValueError('Tracked baseline belongs to a different checkout; run arda track only after verifying identical sources')
    return raw


def write_state(cfg: dict, name: str, head: str, files: dict) -> Path:
    target = state_path(cfg, name)
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    payload = {
        'schema': 1, 'module': name, 'ubuntu': cfg['ubuntu'],
        'aosp_root': cfg['aosp_root'], 'head': head, 'files': files,
        'captured_utc': datetime.now(timezone.utc).isoformat(),
    }
    fd, temporary = tempfile.mkstemp(prefix='.arda-state-', dir=target.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(payload, f, sort_keys=True, indent=2)
            f.write('\n')
        os.chmod(temporary, 0o600)
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)
    return target


def source_fingerprint(files: dict) -> str:
    """Deterministic source checksum of the exclusion-filtered source tree."""
    return hashlib.sha256(json.dumps(files, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def changes(baseline: dict, current: dict) -> dict:
    return {
        'modified': sorted(k for k in baseline.keys() & current.keys() if baseline[k] != current[k]),
        'new': sorted(current.keys() - baseline.keys()),
        'deleted': sorted(baseline.keys() - current.keys()),
    }


def get_context(cfg: dict, name: str):
    from .cli import ArdaError, remote, stage_source
    if name not in BUILD_ENABLED or PROFILES[name]['confidence'] != 'confirmed_v42':
        raise ArdaError('Build not enabled for this profile; V1.3 supports only DirectRenderingCluster')
    local = local_root(cfg, name)
    if not local.is_dir():
        raise ArdaError(f'Mac source missing. Run: arda pull {name}')
    inventory = remote(cfg, 'modules', names=[name], limit=1)
    if not inventory['available'] or len(inventory['rows']) != 1:
        raise ArdaError('Module inventory missing. No build started; check arda list --all --search ...')
    item = inventory['rows'][0]
    if (name != item['name'] or BUILD_ENABLED[name] not in item['path'] or 'APPS' not in item['class']):
        raise ArdaError('AOSP module inventory does not match confirmed APK profile')
    source = remote(cfg, 'source', source=PROFILES[name]['source'])
    if not source.get('exists') or not source.get('git') or not re.fullmatch('[0-9a-f]{40}', source.get('head') or ''):
        raise ArdaError('Ubuntu source or Git HEAD unavailable')
    return local, source


def prepare(cfg, name: str, *, compare_remote=True):
    from .cli import ArdaError, stage_source
    local, info = get_context(cfg, name)
    current = snapshot(local)
    baseline = read_state(cfg, name)
    if not current:
        raise ArdaError('Local source empty; refusing build')
    result = {'name': name, 'local': local, 'head': info['head'], 'files': current, 'baseline': baseline,
              'local_changes': changes(baseline['files'], current) if baseline else None}
    if compare_remote:
        with tempfile.TemporaryDirectory(prefix='arda-build-snapshot-') as stage_dir:
            stage_source(cfg, name, Path(stage_dir))
            result['remote_files'] = snapshot(Path(stage_dir))
    return result


def guard_plan(state, sync: bool) -> dict:
    """Pure safety decision. No writes and no remote commands."""
    baseline = state['baseline']
    mac, ubuntu = state['files'], state['remote_files']
    remote_delta = changes(baseline['files'], ubuntu) if baseline else None
    local_delta = changes(baseline['files'], mac) if baseline else None
    result = {'module': state['name'], 'head': state['head'], 'local_files': len(mac),
              'remote_files': len(ubuntu), 'baseline': bool(baseline), 'sync_requested': sync,
              'local_delta': local_delta, 'remote_delta': remote_delta,
              'local_remote': changes(ubuntu, mac), 'reason': '', 'ready': False, 'will_sync': False}
    if mac == ubuntu:
        if baseline is not None and (baseline['head'] != state['head'] or baseline['files'] != ubuntu):
            result['reason'] = 'Tracked baseline stale; use `arda track MODULE` while sources match'
        else:
            result['ready'] = True
            result['reason'] = 'Sources identical; Ubuntu AOSP build may proceed'
        return result
    if baseline is None:
        result['reason'] = 'No common tracked baseline. Cannot attribute source differences safely.'
        return result
    if baseline['head'] != state['head'] or baseline['files'] != ubuntu:
        result['reason'] = 'Ubuntu source changed since tracked baseline; refusing to overwrite.'
        return result
    if local_delta['deleted']:
        result['reason'] = 'Mac source deletions not supported in V1.3; nothing transferred.'
        return result
    touched = local_delta['modified'] + local_delta['new']
    if not touched or any(mac[p].startswith('SYMLINK:') or not valid_relative(p) for p in touched):
        result['reason'] = 'Unsafe or ambiguous local changes (including symlinks)'
        return result
    if not sync:
        result['reason'] = 'Local modifications need explicit --sync; no transfer occurred'
        return result
    result['ready'] = True
    result['will_sync'] = True
    result['reason'] = 'Tracked baseline matches Ubuntu; guarded transfer is possible'
    return result


def cmd_track(cfg: dict, name: str):
    from .cli import ArdaError
    state = prepare(cfg, name)
    if state['files'] != state['remote_files']:
        raise ArdaError('Mac and Ubuntu differ. Cannot establish common baseline; inspect arda diff first.')
    p = write_state(cfg, name, state['head'], state['files'])
    print(f'TRACKED={name} HEAD={state["head"]} FILES={len(state["files"])}')
    print('BASELINE=' + str(p))
    print('Ubuntu Git/source unchanged. Mac edits can now be compared safely.')
    return 0


def display_plan(data: dict, cfg: dict):
    print('ARDA BUILD PLAN (NO SOURCE WRITES)')
    print('  Module:       ' + data['module'])
    print('  Ubuntu:       ' + cfg['ubuntu'])
    print('  Git HEAD:     ' + data['head'])
    print('  Lunch:        ' + cfg['lunch'])
    print('  Target:       m -jN ' + data['module'])
    print('  Local files:  ' + str(data['local_files']))
    print('  Baseline:     ' + ('tracked' if data['baseline'] else 'none; auto-recorded only when sources are identical'))
    if data['local_delta']:
        d = data['local_delta']
        print(f"  Mac changes:  +{len(d['new'])} ~{len(d['modified'])} -{len(d['deleted'])}")
    print('  Transfer:     ' + ('explicit guarded --sync' if data['will_sync'] else 'NONE'))
    print('  Decision:     ' + ('READY' if data['ready'] else 'STOP'))
    print('  Reason:       ' + data['reason'])
    print('  No repo sync, install, reboot, Git commit or push.')


def ssh_cmd(cfg, script: str):
    from .cli import ssh_flags
    return ['ssh', '-T', *ssh_flags(cfg), cfg['ubuntu'], 'bash -lc ' + shlex.quote(script)]


def sync_files(cfg, state: dict, delta: dict) -> dict:
    """Upload only changed regular files and apply via checked remote transaction."""
    from .cli import ArdaError, run, ssh_flags
    import secrets
    remote_stage = None
    staging_tag = secrets.token_hex(8)
    try:
        mkdir = run(ssh_cmd(cfg, 'umask 077; mktemp -d /tmp/arda-cli-build.' + staging_tag + '.XXXXXXXX'), timeout=25)
        if mkdir.returncode:
            raise ArdaError('Remote staging allocation failed: ' + mkdir.stderr[-300:])
        remote_stage = mkdir.stdout.strip()
        if not re.fullmatch(r'/tmp/arda-cli-build\.[a-f0-9]{16}\.[A-Za-z0-9]{8}', remote_stage):
            raise ArdaError('Unsafe unexpected remote staging path')
        with tempfile.TemporaryDirectory(prefix='arda-build-payload-') as td:
            archive = Path(td) / 'changes.tar'
            files = delta['modified'] + delta['new']
            manifest = {'schema': 1, 'source': PROFILES[state['name']]['source'],
                        'expected_head': state['head'], 'baseline': state['baseline']['files'],
                        'changed': {p: state['files'][p] for p in files}}
            with tarfile.open(archive, 'w') as tar:
                payload = json.dumps(manifest, sort_keys=True).encode('utf-8')
                header = tarfile.TarInfo('manifest.json'); header.size = len(payload); header.mode = 0o600
                tar.addfile(header, io.BytesIO(payload))
                for rel in files:
                    src = state['local'] / rel
                    if src.is_symlink() or not src.is_file():
                        raise ArdaError('Non-regular local file in sync: ' + rel)
                    before = src.stat()
                    # Count bytes before inclusion to prevent path/size surprises.
                    if before.st_size > MAX_ARCHIVE_SIZE:
                        raise ArdaError('Source file larger than safe sync limit: ' + rel)
                    with src.open('rb') as source_file:
                        content_check = source_file.read(MAX_ARCHIVE_SIZE + 1)
                    if any(marker in content_check for marker in PRIVATE_KEY_MARKERS):
                        raise ArdaError('Private-key marker detected in source; sync blocked: ' + rel)
                    tar.add(src, arcname='files/' + rel, recursive=False)
                    if src.stat().st_mtime_ns != before.st_mtime_ns or src.stat().st_size != before.st_size:
                        raise ArdaError('Local file changed during staging: ' + rel)
            if archive.stat().st_size > MAX_ARCHIVE_SIZE:
                raise ArdaError('Change payload exceeds 50 MiB safe limit')
            target = cfg['ubuntu'] + ':' + remote_stage + '/changes.tar'
            cp = run(['scp', '-B', '-i', str(cfg['ssh_key']), '-o', 'BatchMode=yes',
                      '-o', 'ConnectTimeout=8', '-o', 'StrictHostKeyChecking=yes',
                      str(archive), target], timeout=180)
            if cp.returncode:
                raise ArdaError('SCP upload failed: ' + cp.stderr[-400:])
            encoded = base64.urlsafe_b64encode(json.dumps({
                'root': cfg['aosp_root'], 'stage': remote_stage,
                'source': PROFILES[state['name']]['source'], 'action': 'apply',
            }).encode()).decode()
            helper = (PACKAGE_ROOT / 'arda_cli' / 'remote_apply.py').read_text('utf-8')
            command = ['ssh', '-T', *ssh_flags(cfg), cfg['ubuntu'], 'python3 - ' + shlex.quote(encoded)]
            result = run(command, timeout=180, input_text=helper)
            try:
                reply = json.loads(result.stdout.strip())
            except ValueError:
                raise ArdaError('Remote sync did not produce valid status: ' + (result.stderr or result.stdout)[-300:])
            if result.returncode or not reply.get('ok'):
                raise ArdaError('Remote guarded sync STOP: ' + str(reply.get('error', result.stderr))[-500:])
            return reply
    finally:
        if remote_stage and re.fullmatch(r'/tmp/arda-cli-build\.[a-f0-9]{16}\.[A-Za-z0-9]{8}', remote_stage):
            try:
                cleanup_token = base64.urlsafe_b64encode(json.dumps({'action': 'cleanup', 'stage': remote_stage}).encode()).decode()
                helper = (PACKAGE_ROOT / 'arda_cli' / 'remote_apply.py').read_text('utf-8')
                command = ['ssh', '-T', *ssh_flags(cfg), cfg['ubuntu'], 'python3 - ' + shlex.quote(cleanup_token)]
                run(command, timeout=25, input_text=helper)
            except Exception:
                pass


def build_shell_command(cfg: dict, module: str, jobs: int) -> str:
    # All command fragments are fixed or validated config. No user shell args.
    script = ('set -eo pipefail; ' +
              'cd ' + shlex.quote(cfg['aosp_root']) + '; ' +
              'test -f build/envsetup.sh; ' +
              'source build/envsetup.sh; ' +
              'lunch ' + shlex.quote(cfg['lunch']) + '; ' +
              'm -j' + str(jobs) + ' ' + shlex.quote(module))
    return 'bash -lc ' + shlex.quote(script)


def run_build_stream(cfg: dict, module: str, jobs: int, logfile: Path) -> int:
    from .cli import ssh_flags
    command = ['ssh', '-T', *ssh_flags(cfg), cfg['ubuntu'], build_shell_command(cfg, module, jobs)]
    print('BUILD_ON_UBUNTU=' + cfg['ubuntu'], flush=True)
    print('BUILD_TARGET=' + module + ' JOBS=' + str(jobs), flush=True)
    print('BUILD_OUTPUT_LIVE=YES', flush=True)
    with logfile.open('x', encoding='utf-8') as log:
        try:
            with subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, text=True, encoding='utf-8',
                                  errors='replace', bufsize=1) as proc:
                for line in proc.stdout:
                    print(line, end='', flush=True)
                    log.write(line)
                return proc.wait()
        except KeyboardInterrupt:
            print('Build interrupted; please verify Ubuntu subprocess state.', flush=True)
            raise


def save_report(cfg, status: dict, logpath: Path | None = None) -> Path:
    cfg['reports'].mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime('%Y%m%d_%H%M%S_%f')
    output = cfg['reports'] / f'ARDA_CLI_V1_3_BUILD_{stamp}.zip'
    with zipfile.ZipFile(output, 'x', zipfile.ZIP_DEFLATED) as z:
        z.writestr('SUMMARY.json', json.dumps(status, indent=2, sort_keys=True))
        if logpath and logpath.exists():
            z.write(logpath, 'build.log')
    print('REPORT_ZIP=' + str(output))
    return output


def cmd_build(cfg: dict, name: str, *, plan: bool, sync: bool, jobs: int):
    from .cli import ArdaError, remote
    if jobs < 1 or jobs > 16:
        raise ArdaError('--jobs must be 1..16')
    if name not in BUILD_ENABLED:
        raise ArdaError('V1.3 build is enabled only for DirectRenderingCluster')
    state = prepare(cfg, name)
    decision = guard_plan(state, sync)
    display_plan(decision, cfg)
    if plan:
        print('RESULT=PLAN_ONLY')
        return 0 if decision['ready'] else 3
    if not decision['ready']:
        raise ArdaError(decision['reason'])
    status = {'version': __version__, 'module': name, 'lunch': cfg['lunch'],
              'head_before': state['head'], 'git_push': False, 'repo_sync': False,
              'device_install': False, 'reboot': False,
              'sync_requested': sync, 'sync_performed': False, 'build': 'NOT_STARTED',
              'source_sha256': None, 'source_file_count': None}
    logpath = None
    try:
        if decision['will_sync']:
            outcome = sync_files(cfg, state, decision['local_delta'])
            status['sync_performed'] = True
            status['sync_backup'] = outcome.get('backup', '')
            status['sync_count'] = outcome.get('applied', 0)
            # Validate exact result from Ubuntu before build, never assume a successful copy.
            after = prepare(cfg, name)
            if after['files'] != after['remote_files'] or after['head'] != state['head']:
                raise ArdaError('Post-transfer verification failed. Build stopped; inspect source and backup.')
            write_state(cfg, name, after['head'], after['files'])
        elif state['baseline'] is None:
            write_state(cfg, name, state['head'], state['files'])
        # Provenance certificate: bind the build report to the exact tracked files
        # and Git commit. Never rely solely on the existence of an APK on disk.
        prebuild = prepare(cfg, name)
        if prebuild['head'] != status['head_before'] or prebuild['files'] != prebuild['remote_files']:
            raise ArdaError('Source drift immediately before build; refusing')
        status['source_sha256'] = source_fingerprint(prebuild['files'])
        status['source_file_count'] = len(prebuild['files'])
        cfg['reports'].mkdir(parents=True, exist_ok=True)
        fd, name_tmp = tempfile.mkstemp(prefix='.arda-build-log-', suffix='.log', dir=cfg['reports'])
        os.close(fd)
        Path(name_tmp).unlink()  # stream function opens exclusive
        logpath = Path(name_tmp)
        ret = run_build_stream(cfg, name, jobs, logpath)
        status['returncode'] = ret
        status['build'] = 'PASS' if ret == 0 else 'FAIL'
        if ret == 0:
            postbuild = prepare(cfg, name)
            if (postbuild['head'] != status['head_before'] or
                postbuild['files'] != postbuild['remote_files'] or
                source_fingerprint(postbuild['files']) != status['source_sha256']):
                raise ArdaError('Source drift during build; APK cannot be trusted')
            apk = remote(cfg, 'apk_artifact')
            status['apk'] = apk
            if not apk.get('available'):
                status['build'] = 'VERIFY_FAILED'
                print('BUILD=VERIFY_FAILED; expected signed APK not found', flush=True)
            else:
                print('APK_SHA256=' + apk['sha256'], flush=True)
                print('APK_PATH=' + apk['path'], flush=True)
    except (Exception, KeyboardInterrupt) as exc:
        status['build'] = 'STOP'
        status['error'] = str(exc)[-600:] if str(exc) else type(exc).__name__
        save_report(cfg, status, logpath)
        if logpath and logpath.exists(): logpath.unlink()
        raise
    save_report(cfg, status, logpath)
    if logpath and logpath.exists(): logpath.unlink()
    print('BUILD=' + status['build'])
    print('APK_NOT_INSTALLED=YES; device unchanged')
    return 0 if status['build'] == 'PASS' else 3
