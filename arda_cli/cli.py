"""ARDA CLI v0.9: guarded builds/tests, audits, and selected source-only publication.

No automatic repo sync, build, deploy, reboot, or background publication.
"""
from __future__ import annotations
import argparse
import base64
import csv
import io
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import zipfile

from . import __version__
from .config import CONFIG_PATH, PROFILES, PACKAGE_ROOT, local_root, profile, read_config


class ArdaError(Exception):
    pass


def run(args, timeout=30, *, input_text=None):
    try:
        return subprocess.run(args, input=input_text, text=True,
                              stdin=subprocess.DEVNULL if input_text is None else None,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=timeout, encoding='utf-8', errors='replace')
    except subprocess.TimeoutExpired:
        raise ArdaError(f'Command timed out after {timeout}s: {args[0]}') from None
    except FileNotFoundError:
        raise ArdaError(f'Command not installed: {args[0]}') from None


def ssh_flags(cfg):
    return ['-i', str(cfg['ssh_key']), '-o', 'BatchMode=yes',
            '-o', 'ConnectTimeout=8', '-o', 'StrictHostKeyChecking=yes',
            '-o', 'NumberOfPasswordPrompts=0']


def remote(cfg, action, **kw):
    if not cfg['ssh_key'].is_file():
        raise ArdaError(f'SSH key not found: {cfg["ssh_key"]}')
    payload = dict(action=action, root=cfg['aosp_root'],
                   product=cfg.get('product_dir'), **kw)
    encoded = base64.urlsafe_b64encode(json.dumps(payload).encode('utf-8')).decode('ascii')
    # Program input is a LOCAL packaged read-only Python probe, piped into Ubuntu.
    script = (PACKAGE_ROOT / 'arda_cli' / 'remote_probe.py').read_text('utf-8')
    cmdline = 'python3 - ' + shlex.quote(encoded)
    result = run(['ssh', '-T', *ssh_flags(cfg), cfg['ubuntu'], cmdline],
                 timeout=230 if action == 'persist_audit' else (170 if action == 'strategy_batch' else (145 if action == 'persist_plan' else (100 if action in ('modules', 'strategy') else 65))), input_text=script)
    try:
        answer = json.loads(result.stdout.strip())
    except ValueError:
        raise ArdaError('Ubuntu SSH probe failed: ' +
                        (result.stderr.strip() or result.stdout.strip())[-700:]) from None
    if result.returncode != 0 or 'error' in answer:
        raise ArdaError('Ubuntu probe stopped: ' + str(answer.get('error', result.stderr))[-600:])
    return answer


def format_table(headers, rows):
    widths = [max(len(str(h)), *(len(str(r[i])) for r in rows)) if rows else len(str(h))
              for i, h in enumerate(headers)]
    print('  '.join(str(h).ljust(widths[i]) for i, h in enumerate(headers)))
    print('  '.join('-' * w for w in widths))
    for r in rows:
        print('  '.join(str(x).ljust(widths[i]) for i, x in enumerate(r)))


def rel_summary(source):
    return source or '(local Mac project)'


def export_inventory(args, data, kind):
    """Export all matching inventory rows, preserving full module paths/classes.

    Files are created exclusively; existing files are never overwritten.
    """
    output = Path(args.export).expanduser()
    if output.suffix.lower() not in ('.csv', '.json'):
        raise ArdaError('Export file must end with .csv or .json')
    # Avoid following an existing symlink or silently destroying earlier exports.
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        with output.open('x', encoding='utf-8', newline='') as fd:
            if output.suffix.lower() == '.json':
                json.dump({'kind': kind, 'source': data.get('path'),
                           'matches': data['matches'], 'total': data['total'],
                           'rows': data['rows']}, fd, ensure_ascii=False, indent=2)
                fd.write('\n')
            else:
                writer = csv.writer(fd)
                if kind == 'modules':
                    writer.writerow(('module', 'class', 'source_path'))
                    for x in data['rows']:
                        writer.writerow((x['name'], '; '.join(map(str, x['class'])),
                                         '; '.join(map(str, x['path']))))
                else:
                    writer.writerow(('git_project_path',))
                    for x in data['rows']:
                        writer.writerow((x,))
    except FileExistsError:
        raise ArdaError('Export already exists (refusing to overwrite): ' + str(output)) from None
    print(f'EXPORT={output}')
    print(f'Exported {len(data["rows"])} of {data["matches"]} matching {kind}.')


def cmd_list(cfg, args):
    if args.all and args.projects:
        raise ArdaError('Choose either --all (build modules) or --projects (Git projects).')
    if args.export and not (args.all or args.projects):
        raise ArdaError('--export requires --all or --projects')
    if args.export and args.offset:
        raise ArdaError('Export requires --offset 0 to avoid producing an incomplete file')
    if (args.all or args.projects) and args.changed:
        raise ArdaError('--changed is for managed profiles only')
    effective_full = args.full or bool(args.export)
    if args.projects:
        data = remote(cfg, 'projects', search=args.search or '', limit=args.limit,
                      offset=args.offset, full=effective_full)
        if not data['available']:
            print('AOSP Git inventory unavailable: ' + data.get('warning', 'unknown'))
            return 2
        if args.export:
            export_inventory(args, data, 'projects')
        else:
            print('AOSP Git projects (remote, existing .repo metadata only):')
            for p in data['rows']:
                print('  ' + p)
            print(f"Showing {len(data['rows'])} of {data['matches']} matches; total projects {data['total']}.")
        return 0
    if args.all:
        data = remote(cfg, 'modules', search=args.search or '', limit=args.limit,
                      offset=args.offset, full=effective_full)
        if not data['available']:
            print(data['warning'])
            print('Use `arda list` for curated profiles; optional `arda index refresh` updates metadata.')
            return 2
        if args.export:
            export_inventory(args, data, 'modules')
        else:
            rows = [(x['name'], ','.join(map(str, x['class'])) if args.full else ','.join(map(str, x['class']))[:20],
                     ', '.join(map(str, x['path'])) if args.full else ', '.join(map(str, x['path']))[:74])
                    for x in data['rows']]
            print(f"AOSP build modules from {data['path']}")
            format_table(('MODULE', 'CLASS', 'SOURCE PATH'), rows)
            print(f"Showing {len(rows)} of {data['matches']} matches ({data['total']} modules in inventory).")
            if not args.full and data['matches'] > args.offset + len(rows):
                print(f"Next page: arda list --all --offset {args.offset + len(rows)} --limit {args.limit}")
                print('All matches: arda list --all --full; export: arda list --all --export ~/Downloads/arda-modules.csv')
        return 0
    if args.offset:
        raise ArdaError('--offset requires --all or --projects')
    names = [name for name, p in sorted(PROFILES.items())
             if not args.search or args.search.casefold() in (name + ' ' + p['source']).casefold()]
    if args.changed:
        rows = []
        for name in names:
            p = PROFILES[name]
            if p['kind'] == 'mac-gradle':
                folder = local_root(cfg, name)
                if folder.is_dir() and (folder / '.git').exists():
                    s = run(['git', '-C', str(folder), 'status', '--porcelain=v1', '-uall'], timeout=25)
                    count = len(s.stdout.splitlines()) if s.returncode == 0 else '?'
                    if count: rows.append((name, str(count), 'Mac'))
                continue
            try:
                info = remote(cfg, 'source', source=p['source'])
                if info.get('changed_files'):
                    rows.append((name, info['changed_files'], 'Ubuntu'))
            except ArdaError as exc:
                raise ArdaError(f'Could not check {name}: {exc}') from exc
        print('Changed profiles only (not a scan of all 1000+ AOSP Git projects):')
        format_table(('PROFILE', 'CHANGES', 'HOST'), rows)
        return 0
    rows = []
    for name in names:
        p = PROFILES[name]
        local = local_root(cfg, name)
        rows.append((name, p['kind'], 'YES' if local.is_dir() else '-',
                     'YES' if p['pull'] else 'NO', p['confidence']))
    print('ARDA managed module/project profiles (offline):')
    format_table(('NAME', 'TYPE', 'MAC SOURCE', 'PULL', 'CONFIDENCE'), rows)
    print('For all AOSP targets: arda list --all --search cluster')
    print('For all Git projects: arda list --projects')
    return 0


def cmd_info(cfg, args):
    name = args.module
    if name not in PROFILES:
        data = remote(cfg, 'modules', names=[name], limit=1)
        if not data['available'] or not data['rows']:
            raise ArdaError(f'Unknown module: {name}. See `arda list --all --search ...`.')
        x = data['rows'][0]
        print(f'{name}: discovered AOSP module (read-only, not yet managed)')
        print('  AOSP paths: ' + ', '.join(x['path']))
        print('  Classes:    ' + ', '.join(x['class']))
        print('  Pull/build/test/persist not enabled until a safe profile is registered.')
        return 0
    p = profile(name)
    local = local_root(cfg, name)
    print(f'Module/project: {name}')
    print(f"  Type:        {p['kind']}")
    print(f"  Build name:  {p['module']} ({p['confidence']})")
    print(f"  Ubuntu path: {cfg['aosp_root']}/{p['source']}" if p['source'] else '  Ubuntu path: n/a')
    print(f'  Mac path:    {local}')
    print(f"  Pull:        {'enabled' if p['pull'] else 'disabled (safety)'}")
    print('  Build:        enabled with guarded sync' if name == 'DirectRenderingCluster' else '  Build:        not enabled (candidate or different build system)')
    print('  Test:         staged APK + verify enabled (manual reboot)' if name == 'DirectRenderingCluster' else '  Test:         not enabled')
    print('  Persist:      read-only plan supported; publication not implemented')
    if p['kind'] == 'mac-gradle':
        print('  Local exists:', 'yes' if local.is_dir() else 'no')
        return 0
    info = remote(cfg, 'source', source=p['source'])
    print(f"  Ubuntu exists: {'yes' if info['exists'] else 'NO'}")
    if info.get('git'):
        print(f"  Ubuntu Git: {info.get('head', 'unknown')}")
        print(f"  Changed files: {info.get('changed_files', '?')}")
    mods = remote(cfg, 'modules', names=[p['module']], limit=1)
    if mods['available']:
        found = mods['rows']
        print('  Module-info: ' + ('confirmed in inventory' if found else 'NOT found (candidate only)'))
        if found: print('  Indexed path: ' + ', '.join(found[0]['path']))
    else:
        print('  Module-info: absent; no build triggered')
    return 0


def cmd_status(cfg, args):
    print('ARDA CLI v' + __version__)
    print('  Ubuntu: ', cfg['ubuntu'])
    print('  AOSP:   ', cfg['aosp_root'])
    print('  Device: ', cfg['device'], '(not modified)')
    rows = []
    for name, p in PROFILES.items():
        loc = local_root(cfg, name)
        locstate = 'local' if loc.is_dir() else '-'
        remstate = 'Mac project'
        if p['source']:
            data = remote(cfg, 'source', source=p['source'])
            remstate = 'missing'
            if data.get('exists'):
                num = data.get('changed_files')
                remstate = 'dirty '+str(num) if num else ('clean' if num == 0 else 'source')
        rows.append((name, locstate, remstate))
    format_table(('NAME', 'MAC', 'UBUNTU SOURCE'), rows)
    print('Git clean here does not prove remote GitHub/manifest pins or device deployment.')
    return 0


def cmd_doctor(cfg, args):
    checks = {}
    checks['ssh_key'] = cfg['ssh_key'].is_file()
    checks['local_ssh'] = shutil.which('ssh') is not None
    checks['local_rsync'] = shutil.which('rsync') is not None
    checks['local_git'] = shutil.which('git') is not None
    checks['local_adb'] = shutil.which('adb') is not None
    print('Local tools:')
    for k, v in checks.items(): print(f"  {k}: {'PASS' if v else 'MISSING'}")
    data = None
    try:
        paths = sorted({p['source'] for p in PROFILES.values() if p['source']})
        data = remote(cfg, 'doctor', paths=paths)
        print('Ubuntu (read-only):')
        for k, v in data['checks'].items():
            print(f"  {k}: {'PASS' if v else 'UNAVAILABLE'}")
        for k, v in data['sources'].items():
            print(f"  source {k}: {'exists' if v else 'NOT FOUND'}")
    except ArdaError as exc:
        print('Ubuntu unreachable: ' + str(exc))
    if checks['local_adb']:
        try:
            r = run(['adb', '-s', cfg['device'], 'get-state'], timeout=12)
            print('Device (read-only): ' + ('connected' if r.returncode == 0 and r.stdout.strip() == 'device' else 'not ready'))
        except ArdaError as exc:
            print('Device: ' + str(exc))
    if args.report:
        report(cfg, 'doctor', {'local': checks, 'ubuntu': data})
    return 0 if all(checks.values()) and data is not None and data['checks']['aosp_root'] else 2


def file_map(folder):
    """Hash regular files; symlinks recorded as links, never dereferenced."""
    output = {}
    if not folder.exists():
        return output
    if folder.is_symlink():
        raise ArdaError('Refusing symlink checkout: ' + str(folder))
    for base, dirs, files in os.walk(folder, followlinks=False):
        base = Path(base)
        for name in list(dirs):
            p = base / name
            if p.is_symlink():
                output[str(p.relative_to(folder))] = 'SYMLINK:' + os.readlink(p)
                dirs.remove(name)
        for name in files:
            p = base / name
            key = str(p.relative_to(folder))
            if p.is_symlink():
                output[key] = 'SYMLINK:' + os.readlink(p)
            elif p.is_file():
                h = hashlib.sha256()
                with p.open('rb') as fd:
                    for block in iter(lambda: fd.read(1024 * 1024), b''):
                        h.update(block)
                output[key] = h.hexdigest()
    return output


def compare(dst, stage):
    ours, theirs = file_map(dst), file_map(stage)
    changed = [p for p in (ours.keys() & theirs.keys()) if ours[p] != theirs[p]]
    return {'local_only': sorted(ours.keys() - theirs.keys()),
            'remote_only': sorted(theirs.keys() - ours.keys()),
            'different': sorted(changed),
            'same': len(set(ours.keys()) & set(theirs.keys())) - len(changed)}


def stage_source(cfg, module, stage):
    p = profile(module)
    if not p['pull']:
        raise ArdaError(f'Pull disabled for {module}: shared/secret-bearing project or Mac-native source')
    info = remote(cfg, 'source', source=p['source'])
    if not info['exists']:
        raise ArdaError(f'Ubuntu source missing: {p["source"]}')
    if not shutil.which('rsync'):
        raise ArdaError('rsync is required on Mac')
    # Explicit exclusions: no Git metadata, build products or plausible secrets.
    excludes = ['.git/', '.repo/', '.arda-backups/', 'out/', 'build/', '.gradle/',
                'signing/', '*.pk8', '*.pem', '*.key', '*.jks', '*.keystore',
                '*.p12', '*.pfx', '*.mobileprovision', '.DS_Store', '*.env']
    rsh = ' '.join(shlex.quote(x) for x in ['ssh', *ssh_flags(cfg)])
    source = f"{cfg['ubuntu']}:{cfg['aosp_root'].rstrip('/')}/{p['source']}/"
    command = ['rsync', '-a', '--no-owner', '--no-group', '-e', rsh]
    for excluded in excludes:
        command += ['--exclude', excluded]
    command += [source, str(stage) + '/']
    cp = run(command, timeout=220)
    if cp.returncode:
        raise ArdaError('rsync failed (nothing merged into Mac project): ' + cp.stderr[-650:])


def report(cfg, action, data):
    folder = cfg['reports']
    folder.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    out = folder / f'ARDA_CLI_V1_{action.upper()}_{stamp}.zip'
    # All reports contain metadata only, never sources, APKs or signing material.
    with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED) as z:
        z.writestr('SUMMARY.json', json.dumps({
            'version': __version__, 'action': action, 'created': datetime.now().isoformat(),
            'ubuntu': cfg['ubuntu'], 'data': data,
            'no_build': True, 'no_repo_sync': True, 'no_reboot': True,
            'no_push': True, 'no_install': True,
        }, indent=2, ensure_ascii=False))
    print('REPORT_ZIP=' + str(out))
    return out


def cmd_copy(cfg, args):
    name = args.module
    p = profile(name)
    target = local_root(cfg, name)
    if not p['pull']:
        raise ArdaError(f'{name} is not eligible for remote pull in v0.1')
    target.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix='.arda-stage-', dir=target.parent))
    stat = {'module': name, 'target': str(target), 'action': args.action}
    try:
        stage_source(cfg, name, stage)
        stat['remote_sha256_file_count'] = len(file_map(stage))
        if not target.exists() and not target.is_symlink():
            delta = {'local_only': [], 'remote_only': [], 'different': [], 'same': 0}
            if args.action == 'pull' and not args.dry_run:
                stage.rename(target)
                stat['result'] = 'NEW_SOURCE_PULLED'
            else:
                stat['result'] = 'LOCAL_SOURCE_ABSENT'
        else:
            delta = compare(target, stage)
            if not delta['different'] and not delta['local_only'] and not delta['remote_only']:
                stat['result'] = 'IDENTICAL'
            elif args.action == 'diff' or args.dry_run:
                stat['result'] = 'DIFFERENCES_FOUND'
            elif not args.backup:
                stat['result'] = 'STOP_LOCAL_DIFFERENCES'
            else:
                backup = target.parent / (target.name + '.arda-backup-' + datetime.now().strftime('%Y%m%d_%H%M%S_%f'))
                target.rename(backup)
                try:
                    stage.rename(target)
                except Exception:
                    backup.rename(target)
                    raise
                stat['backup'] = str(backup)
                stat['result'] = 'PULLED_WITH_BACKUP'
        stat['diff'] = {k: len(v) if isinstance(v, list) else v for k, v in delta.items()}
        print(name + ' -> ' + str(target))
        print('RESULT=' + stat['result'])
        for heading in ['different', 'local_only', 'remote_only']:
            entries = delta[heading]
            if entries:
                print(f'  {heading}: {len(entries)}')
                for entry in entries[:20]: print('    ' + entry)
                if len(entries) > 20: print('    ... truncated')
        if stat.get('backup'): print('BACKUP=' + stat['backup'])
        if args.action == 'pull' or args.report:
            report(cfg, args.action, stat)
        if stat['result'] == 'STOP_LOCAL_DIFFERENCES':
            print('Local files were NOT modified. Use `arda diff MODULE` first;')
            print('only use `arda pull MODULE --backup` if an archival copy is acceptable.')
            return 3
        return 0
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def index_refresh_command(cfg):
    """Build metadata ONLY, on Ubuntu, if explicitly invoked by user."""
    lunch = cfg['lunch']
    root = cfg['aosp_root']
    # Fixed command names, strictly validated config; shell quotes for paths.
    remote_script = ('set -eo pipefail; '
                     'cd ' + shlex.quote(root) + '; '
                     'test -f build/envsetup.sh; '
                     'source build/envsetup.sh; '
                     'lunch ' + shlex.quote(lunch) + '; '
                     'm module-info')
    return ['ssh', '-T', *ssh_flags(cfg), cfg['ubuntu'],
            'bash -lc ' + shlex.quote(remote_script)]


def cmd_index(cfg, args):
    if args.index_action != 'refresh':
        raise ArdaError('Unknown index action')
    cmd = index_refresh_command(cfg)
    print('Refreshing AOSP module-info.json on Ubuntu (metadata target only).', flush=True)
    print('  Ubuntu: ' + cfg['ubuntu'], flush=True)
    print('  Lunch:  ' + cfg['lunch'], flush=True)
    print('  Product out: ' + cfg.get('product_dir', 'auto'), flush=True)
    print('  Target: m module-info', flush=True)
    print('  NO repo sync, full OS image build, APK install, device reboot or Git push.', flush=True)
    if args.dry_run:
        print('DRY_RUN=YES (nothing executed)')
        return 0
    if not cfg['ssh_key'].is_file():
        raise ArdaError('SSH key missing: ' + str(cfg['ssh_key']))
    stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    cfg['reports'].mkdir(parents=True, exist_ok=True)
    log_path = cfg['reports'] / f'ARDA_CLI_V1_1_INDEX_REFRESH_{stamp}.log'
    report_path = cfg['reports'] / f'ARDA_CLI_V1_1_INDEX_REFRESH_{stamp}.zip'
    try:
        with log_path.open('x', encoding='utf-8') as logfile:
            with subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, text=True,
                                  encoding='utf-8', errors='replace', bufsize=1) as proc:
                for line in proc.stdout:
                    print(line, end='', flush=True)
                    logfile.write(line)
                status = proc.wait()
        # Preserve log in report zip. Do not claim a successful refresh based solely on exit=0.
        report_data = {'version': __version__, 'action': 'index_refresh',
                       'lunch': cfg['lunch'], 'product': cfg.get('product_dir'), 'target': 'module-info',
                       'returncode': status, 'no_repo_sync': True, 'no_device_change': True}
        with zipfile.ZipFile(report_path, 'w', zipfile.ZIP_DEFLATED) as z:
            z.writestr('SUMMARY.json', json.dumps(report_data, indent=2))
            z.write(log_path, 'index-refresh.log')
        log_path.unlink()
        print('REPORT_ZIP=' + str(report_path))
        if status != 0:
            print('INDEX_REFRESH=FAILED; prior module-info.json may still be present.', file=sys.stderr)
            return 3
        # Read fresh inventory metadata; may still choose a previously indexed path if multiple products.
        data = remote(cfg, 'modules', search='', limit=1)
        if not data['available']:
            print('INDEX_REFRESH=BUILD_SUCCESS_BUT_INVENTORY_MISSING', file=sys.stderr)
            return 3
        print(f"INDEX_REFRESH=PASS; indexed modules: {data['total']} ({data['path']})")
        return 0
    except OSError as exc:
        raise ArdaError(f'Index refresh failed: {exc}') from exc


# ---- v0.3 source strategy advisor (never migrates, commits or pushes) ----

def _strategy_known(source):
    from .release_refs import RECORDS
    return RECORDS.get(source, {})


def _current_strategy(item, record=None, mac_project=False):
    """Classify ownership/provenance; no conclusion solely from module name."""
    record = record or {}
    if record.get('strategy'):
        return record['strategy'], 'recorded_' + record['release']
    if not item.get('git'):
        return 'UNMANAGED', 'git_unavailable'
    owners = {x.get('owner') for x in item.get('remotes', [])}
    manifest = item.get('manifest') or {}
    if manifest.get('owner') == 'Deadknight' or 'Deadknight' in owners:
        return ('DIRECT' if mac_project or str(item.get('repo_path', '')).startswith('vendor/arda/')
                else 'FORK'), 'local_git_or_manifest'
    if owners & {'AOSP', 'raspberry-vanilla', 'github-third-party'} or manifest.get('owner') in ('AOSP', 'raspberry-vanilla'):
        return 'UPSTREAM', 'local_git_or_manifest'
    return 'UNMANAGED', 'no_confirmed_owner'


def _release_state(item, record):
    if not record: return 'UNTRACKED'
    if not item.get('head'): return 'UNKNOWN'
    if item['head'] == record['release_head']: return 'MATCH'
    # A different HEAD may have new valid changes; not an error by itself.
    return 'DIFFERS_FROM_RELEASE'


def _patch_evaluation(item):
    metrics = item.get('base_diff')
    if not metrics:
        return 'NOT_ASSESSED', 'No verified upstream base SHA; do not infer patch suitability.'
    if not metrics.get('measured'):
        return 'INDETERMINATE', metrics.get('error', 'Unable to measure source divergence')
    churn = metrics['lines_added'] + metrics['lines_deleted']
    if metrics['binary_files']:
        return 'FORK_FAVORED', 'Changed binary files; a patch may be possible but requires explicit review.'
    if metrics['files'] > 35 or churn > 2500:
        return 'FORK_FAVORED', 'Broad divergence; fork is easier to audit and maintain.'
    if metrics['files'] <= 8 and churn <= 500:
        return 'PATCH_CANDIDATE', 'Small text-only committed diff; clean replay has NOT been verified.'
    return 'REVIEW', 'Patch could work; dependency and clean-replay audit still required.'


def assess_strategy(raw, record=None, *, mac_project=False):
    record = record or {}
    result = dict(raw)
    mode, proof = _current_strategy(result, record, mac_project)
    result['strategy'] = mode
    result['strategy_evidence'] = proof
    from .release_refs import RELEASE_MANIFEST_SHA
    result['release_record'] = ({'release': record['release'],
                                 'release_head': record['release_head'],
                                 'manifest_sha': RELEASE_MANIFEST_SHA} if record else None)
    result['release_status'] = _release_state(result, record)
    rating, note = _patch_evaluation(result)
    result['patch_assessment'] = rating
    result['patch_reason'] = note
    result['suggestion'] = ('KEEP_EXISTING' if mode in ('PATCH', 'DIRECT', 'FORK')
                            else 'REVIEW_OWNERSHIP')
    if result.get('base_origin') == 'manual_unverified' and rating == 'PATCH_CANDIDATE':
        result['patch_assessment'] = 'PATCH_CANDIDATE_BASE_UNVERIFIED'
        result['patch_reason'] += ' Supplied SHA is not proven to be the upstream base.'
    if mode == 'FORK' and result['patch_assessment'] == 'PATCH_CANDIDATE':
        result['suggestion'] = 'OPTIONAL_PATCH_MIGRATION_REVIEW'
    result['safety'] = 'READ_ONLY; no GitHub changes, migrations or builds'
    return result


def _local_mac_strategy(cfg, name, base):
    from .remote_probe import git_read, git_remotes, diff_metrics
    loc = local_root(cfg, name)
    if not loc.is_dir():
        return {'source': name, 'exists': False, 'repo_path': name, 'error': 'Mac project folder not present'}
    rc, top, _ = git_read(loc, 'rev-parse', '--show-toplevel')
    if rc:
        return {'source': name, 'exists': True, 'git': False,
                'repo_path': name, 'error': 'Mac project not a Git checkout'}
    top = Path(top)
    if not top.resolve().is_relative_to(loc.resolve()):
        raise ArdaError('Mac project Git root escapes configured project directory')
    rc, head, _ = git_read(top, 'rev-parse', 'HEAD')
    rc2, status, _ = git_read(top, 'status', '--porcelain=v1', '-uall')
    result = {'source': name, 'repo_path': name, 'exists': True, 'git': True,
              'head': head if rc == 0 else None,
              'dirty_files': len(status.splitlines()) if rc2 == 0 else None,
              'remotes': git_remotes(top), 'manifest': None, 'manifest_warnings': [],
              'shallow': None}
    if base and head: result['base_diff'] = diff_metrics(top, base, head)
    return result


def _module_source(cfg, module):
    if module in PROFILES:
        return PROFILES[module]['source'] or None
    if '/' in module:
        # Path is validated again by the Ubuntu read-only probe.
        if module.startswith('/') or '..' in Path(module).parts:
            raise ArdaError('Invalid module/project path')
        return module
    mod = remote(cfg, 'modules', names=[module], limit=1)
    if not mod.get('available') or not mod.get('rows'):
        raise ArdaError(f'Unknown AOSP module: {module}. Try `arda list --all --search ...`.')
    paths = mod['rows'][0].get('path', [])
    if len(paths) != 1:
        raise ArdaError(f'Module {module} has {len(paths)} source paths; pass Git project path explicitly.')
    return paths[0]


def _strategy_one(cfg, module, base=None):
    if base and (len(base) != 40 or any(ch not in '0123456789abcdefABCDEF' for ch in base)):
        raise ArdaError('--base requires a complete 40-character Git commit SHA')
    if module in PROFILES and PROFILES[module]['kind'] == 'mac-gradle':
        raw = _local_mac_strategy(cfg, module, base)
        return assess_strategy(raw, _strategy_known(module), mac_project=True)
    src = _module_source(cfg, module)
    known = _strategy_known(src)
    base = base or known.get('baseline')
    raw = remote(cfg, 'strategy', source=src, base=base)
    raw['base_origin'] = ('manual_unverified' if base and (not known.get('baseline') or base != known['baseline'])
                          else 'v49.7_release' if base else 'unavailable')
    # Compare historical reference ONLY if discovered Git repo path matches.
    known = _strategy_known(raw.get('repo_path', ''))
    return assess_strategy(raw, known)


def _strategy_batch(cfg, names, *, paths=False):
    items, records, result = [], [], []
    for name in names:
        if not paths and PROFILES[name]['kind'] == 'mac-gradle':
            result.append((name, assess_strategy(_local_mac_strategy(cfg, name, None),
                                                _strategy_known(name), mac_project=True)))
            continue
        source = name if paths else PROFILES[name]['source']
        record = _strategy_known(source)
        items.append({'source': source, 'base': record.get('baseline')})
        records.append((name, source))
    if items:
        data = remote(cfg, 'strategy_batch', items=items)
        rows = data.get('rows', [])
        if len(rows) != len(items): raise ArdaError('Incomplete strategy response from Ubuntu')
        for (name, _), raw in zip(records, rows):
            raw['base_origin'] = 'v49.7_release' if raw.get('base_diff') else 'unavailable'
            result.append((name, assess_strategy(raw, _strategy_known(raw.get('repo_path', '')))))
    return result


def _strategy_print_one(name, data, show_plan=False):
    print('ARDA SOURCE STRATEGY (READ-ONLY)')
    print('  Requested:        ' + name)
    print('  Git project:      ' + str(data.get('repo_path', '?')))
    print('  Local HEAD:       ' + str(data.get('head', 'unavailable')))
    print('  Current strategy: ' + data['strategy'] + ' (' + data['strategy_evidence'] + ')')
    print('  Working changes:  ' + str(data.get('dirty_files', 'unknown')))
    print('  Release record:   ' + data['release_status'])
    if data.get('release_record'):
        print('  Checkpoint:       ' + data['release_record']['release'])
    for r in data.get('remotes', []):
        print(f"  Git remote {r['name']}: {r['url']} [{r['owner']}]")
    if data.get('manifest'):
        m = data['manifest']
        print('  Local manifest:   ' + str(m.get('name', '?')) + ' remote=' + str(m.get('remote', '?')))
        print('  Manifest rev:     ' + str(m.get('revision', '?')))
    else:
        print('  Local manifest:   not resolved (Git ownership not necessarily known)')
    for warning in data.get('manifest_warnings', [])[:3]:
        print('  Manifest note:    ' + warning)
    diff = data.get('base_diff')
    if diff:
        print('  Upstream base:    ' + diff['base'])
        if diff.get('measured'):
            print(f"  Committed diff:   {diff['files']} files, +{diff['lines_added']} / -{diff['lines_deleted']}, {diff['binary_files']} binary")
        else:
            print('  Base validation:  ' + diff.get('error', 'unknown'))
    if data.get('base_origin'):
        print('  Base provenance:  ' + data['base_origin'])
    print('  Patch analysis:   ' + data['patch_assessment'])
    print('  Reason:           ' + data['patch_reason'])
    print('  Recommendation:   ' + data['suggestion'])
    if data.get('dirty_files'):
        print('  CAUTION:          Uncommitted files are NOT included in committed-diff metrics.')
    if show_plan:
        print('  OPTIONAL PLAN (no actions performed):')
        if data['suggestion'] == 'OPTIONAL_PATCH_MIGRATION_REVIEW':
            print('    1. Keep current fork and pinned SHA unchanged.')
            print('    2. Verify clean upstream base and recreate exact source tree with a patch.')
            print('    3. Test clean bootstrap/build before creating a NEW manifest checkpoint.')
        else:
            print('    1. Preserve current release and Git commit pointers.')
            print('    2. Establish verified upstream base if an alternative is needed.')
            print('    3. Do not migrate without a clean-replay and build validation.')
    print('RESULT=READ_ONLY_NO_CHANGES')


def cmd_strategy(cfg, args):
    if args.all and args.projects:
        raise ArdaError('Choose only one of --all and --projects.')
    if args.module and (args.all or args.projects):
        raise ArdaError('Specify either module or --all/--projects, not both.')
    if not args.module and not args.all and not args.projects:
        raise ArdaError('Supply a module/Git path or use --all/--projects.')
    if args.json and args.report:
        raise ArdaError('Choose --json or --report (pure JSON cannot include REPORT_ZIP line).')
    if args.module and args.search:
        raise ArdaError('--search only applies to --all or --projects.')
    if args.base and (args.all or args.projects):
        raise ArdaError('--base only applies to one module/project.')
    if args.projects:
        proj = remote(cfg, 'projects', search=args.search or '', limit=args.limit, offset=0)
        if not proj.get('available'):
            raise ArdaError('Git project inventory unavailable')
        if not proj.get('rows'):
            print('[]' if args.json else 'No matching Git projects.'); return 0
        assessed = _strategy_batch(cfg, proj['rows'], paths=True)
        if not args.json:
            print(f"Project scan: {len(assessed)} of {proj['matches']} matching Git projects; no fetch/build.")
    elif args.all:
        names = [n for n, p in sorted(PROFILES.items()) if not args.search or
                 args.search.casefold() in (n + ' ' + p['source']).casefold()]
        assessed = _strategy_batch(cfg, names)
        if not args.json:
            print(f'Managed profiles: {len(assessed)}; no fetch/build.')
    else:
        data = _strategy_one(cfg, args.module, args.base)
        assessed = [(args.module, data)]
    if args.json:
        print(json.dumps([{'module': name, **data} for name, data in assessed], indent=2, ensure_ascii=False))
    elif len(assessed) == 1:
        _strategy_print_one(*assessed[0], show_plan=args.plan)
    else:
        rows = [(name, data.get('repo_path','?'), data['strategy'], data['patch_assessment'],
                 data['release_status'], str(data.get('dirty_files', '?')))
                for name, data in assessed]
        format_table(('MODULE/PROJECT', 'GIT PATH', 'CURRENT', 'PATCH?', 'CHECKPOINT', 'DIRTY'), rows)
        print('No automatic strategy migration. For detail: arda strategy <module-or-project> --plan')
    if args.report:
        report(cfg, 'strategy', {'rows': [{'module': name, **data} for name, data in assessed]})
    return 0


def parser():
    p = argparse.ArgumentParser(prog='arda', description='ARDA AAOS project manager (v1.17 guarded infrastructure migration)')
    p.add_argument('--version', action='version', version=f'arda {__version__}')
    sub = p.add_subparsers(dest='action', required=True)
    a = sub.add_parser('list', help='managed modules; --all AOSP module inventory; --projects Git paths')
    a.add_argument('--all', action='store_true', help='all indexed AOSP build modules (no build)')
    a.add_argument('--projects', action='store_true', help='AOSP Git project paths')
    a.add_argument('--changed', action='store_true', help='changed MANAGED profiles only')
    a.add_argument('--search', default='', help='substring filter')
    a.add_argument('--limit', type=int, default=80, help='rows per page (1..1000; default 80)')
    a.add_argument('--offset', type=int, default=0, help='skip N matching rows for pagination')
    a.add_argument('--full', action='store_true', help='show every matching row, no limit')
    a.add_argument('--export', metavar='FILE.csv|FILE.json', help='export ALL matching rows without terminal spam; never overwrites')
    a = sub.add_parser('index', help='optional AOSP module-info inventory maintenance')
    idx = a.add_subparsers(dest='index_action', required=True)
    a = idx.add_parser('refresh', help='explicitly rebuild module-info.json metadata on Ubuntu')
    a.add_argument('--dry-run', action='store_true', help='show planned target, no build')
    a = sub.add_parser('strategy', help='read-only fork vs patch analysis (no migration)')
    a.add_argument('module', nargs='?', help='build module or AOSP Git project path')
    a.add_argument('--base', help='explicit 40-character upstream baseline commit; local only, no fetch')
    a.add_argument('--all', action='store_true', help='audit all managed profiles')
    a.add_argument('--projects', action='store_true', help='audit existing AOSP Git projects (paginated)')
    a.add_argument('--search', default='', help='project path/profile filter')
    a.add_argument('--limit', type=int, default=30, help='--projects scan limit (1..100)')
    a.add_argument('--plan', action='store_true', help='show non-executable migration checklist')
    a.add_argument('--json', action='store_true', help='emit metadata JSON only')
    a.add_argument('--report', action='store_true', help='write metadata-only ZIP report')
    a = sub.add_parser('org', help='GitHub organization migration; pilot transfer requires explicit confirmation')
    orgsub=a.add_subparsers(dest='org_action',required=True)
    a=orgsub.add_parser('plan',help='inventory repos and check organization readiness without transferring')
    a.add_argument('--target',default='arda-aaos')
    a.add_argument('--report',action='store_true')
    a.add_argument('--json',action='store_true')
    a=orgsub.add_parser('pilot',help='one public, non-critical repo preflight; explicit --apply to transfer')
    a.add_argument('--repo',required=True,help='exact source repo name under Deadknight')
    a.add_argument('--target',default='arda-aaos')
    a.add_argument('--apply',action='store_true',help='EXPLICITLY send GitHub repository transfer request')
    a.add_argument('--confirm',default='',help='must equal: Deadknight/REPO -> arda-aaos/REPO')
    a.add_argument('--report',action='store_true')
    a=orgsub.add_parser('inventory',help='read-only source/target inventory with manifest and Git remote associations')
    a.add_argument('--target',default='arda-aaos')
    a.add_argument('--json',action='store_true')
    a.add_argument('--report',action='store_true')
    a=orgsub.add_parser('wave',help='public independent or remote-linked transfer waves (explicit gated apply)')
    a.add_argument('--target',default='arda-aaos')
    a.add_argument('--phase',choices=('independent','remote'),default='independent',
                   help='independent: max 3 repos; remote: max 1 Git-remote-linked repo without manifest refs')
    a.add_argument('--plan',action='store_true',help='read-only inventory and snapshot (default)')
    a.add_argument('--apply',action='store_true',help='EXPLICIT transfer with per-repo verification and local migration')
    a.add_argument('--repo',action='append',default=[],help='exact repository name; independent max 3, remote max 1')
    a.add_argument('--confirm',default='',help='exact: TRANSFER repo1,repo2 TO arda-aaos')
    a.add_argument('--report',action='store_true')
    a=orgsub.add_parser('reconcile',help='read-only verify transferred repos, pending groups, stale refs and CLI owner policy')
    a.add_argument('--target',default='arda-aaos')
    a.add_argument('--report',action='store_true')
    a.add_argument('--json',action='store_true')
    a=orgsub.add_parser('batch',help='guarded PUBLIC CORE group: remote-linked + active AOSP; no manifest rewrite')
    a.add_argument('--target',default='arda-aaos')
    a.add_argument('--plan',action='store_true',help='read-only source SHA and GitHub ID preflight (default)')
    a.add_argument('--apply',action='store_true',help='transfer the entire frozen verified public core group in sequence')
    a.add_argument('--confirm',default='',help='exact confirmation token printed by --plan')
    a.add_argument('--report',action='store_true')
    a=orgsub.add_parser('tail',help='guarded special-public or private transfers, excluding infrastructure')
    a.add_argument('--target',default='arda-aaos')
    a.add_argument('--phase',choices=('public-special','private'),required=True)
    a.add_argument('--plan',action='store_true',help='read-only frozen full-group GitHub preflight (default)')
    a.add_argument('--apply',action='store_true',help='explicit batch transfer of all frozen phase repos')
    a.add_argument('--confirm',default='',help='exact confirmation token printed by --plan')
    a.add_argument('--report',action='store_true')
    a=orgsub.add_parser('infra',help='final 2 infrastructure repos; private-access and manifest freeze audit, explicit transfer')
    a.add_argument('--target',default='arda-aaos')
    a.add_argument('--plan',action='store_true',help='read-only plan and private access audit (default)')
    a.add_argument('--apply',action='store_true',help='explicitly transfer releases then manifest; no manifest edits')
    a.add_argument('--confirm',default='',help='exact fingerprinted confirmation from plan')
    a.add_argument('--report',action='store_true')
    a=orgsub.add_parser('migrate',help='verify transferred repo and repair exact matching local Git remotes; pilot-only')
    a.add_argument('--repo',required=True,help='exact previously transferred repository name')
    a.add_argument('--target',default='arda-aaos')
    a.add_argument('--plan',action='store_true',help='read-only plan (default)')
    a.add_argument('--apply',action='store_true',help='write verified exact matching Ubuntu Git remote URLs')
    a.add_argument('--confirm',default='',help='required with --apply: Deadknight/REPO -> arda-aaos/REPO')
    a.add_argument('--report',action='store_true')
    a = sub.add_parser('persist', help='--plan/--audit are read-only; bare MODULE publishes a guarded source checkpoint')
    a.add_argument('module', nargs='?', help='managed module; bare MODULE publishes only when changes exist')
    a.add_argument('--all', action='store_true', help='all managed modules')
    a.add_argument('--plan', action='store_true', help='show proposed actions only')
    a.add_argument('--audit', action='store_true', help='verify pinned GitHub commit, patch replay or Launcher fork (read-only)')
    a.add_argument('--json', action='store_true', help='metadata JSON')
    a.add_argument('--report', action='store_true', help='write metadata-only ZIP on Mac')
    a = sub.add_parser('track', help='record common Mac/Ubuntu source baseline for safe future sync')
    a.add_argument('module')
    a = sub.add_parser('build', help='build verified AOSP module on Ubuntu (never deploy)')
    a.add_argument('module')
    a.add_argument('--plan', action='store_true', help='read-only preflight; no source writes or build')
    a.add_argument('--sync', action='store_true', help='explicitly sync local modifications against recorded common baseline')
    a.add_argument('--jobs', type=int, default=4, help='AOSP m parallelism (1..16; default 4)')
    a = sub.add_parser('test', help='stage a provenance-verified Cluster APK; no reboot')
    a.add_argument('module')
    a.add_argument('--plan', action='store_true', help='read-only staging preflight')
    a.add_argument('--build', action='store_true', help='explicit fresh module build before stage')
    a.add_argument('--sync', action='store_true', help='with --build, guarded Mac source upload')
    a.add_argument('--jobs', type=int, default=4)
    a.add_argument('--build-report', help='specific successful V1.4 build report ZIP')
    a = sub.add_parser('verify', help='read-only check staged APK after manual reboot')
    a.add_argument('module')
    a = sub.add_parser('info', help='module details and read-only Ubuntu Git/source info')
    a.add_argument('module')
    sub.add_parser('status', help='read-only state of managed source projects')
    a = sub.add_parser('doctor', help='check Mac/Ubuntu/ADB prerequisites (read-only)')
    a.add_argument('--report', action='store_true', help='create metadata-only report ZIP')
    for cmd in ('pull', 'diff'):
        a = sub.add_parser(cmd, help='safe Ubuntu to Mac copy' if cmd == 'pull' else 'read-only local/Ubuntu source comparison')
        a.add_argument('module')
        a.add_argument('--report', action='store_true')
        a.add_argument('--dry-run', action='store_true', help='compare only, no source replacement')
        a.add_argument('--backup', action='store_true', help='archive existing local project before replacement' if cmd == 'pull' else argparse.SUPPRESS)
    return p


def main(argv=None):
    args = parser().parse_args(argv)
    max_limit = 100 if args.action == 'strategy' else 1000
    if getattr(args, 'limit', 80) < 1 or getattr(args, 'limit', 80) > max_limit:
        print(f'ERROR: --limit must be 1..{max_limit}', file=sys.stderr)
        return 2
    if getattr(args, 'offset', 0) < 0:
        print('ERROR: --offset cannot be negative', file=sys.stderr)
        return 2
    try:
        cfg = read_config()
        if args.action == 'list': return cmd_list(cfg, args)
        if args.action == 'strategy': return cmd_strategy(cfg, args)
        if args.action == 'org':
            if getattr(args, 'apply', False):
                raise ArdaError('Owner migration complete: historical org --apply paths are HOLD pending separate review')
            if args.org_action == 'pilot':
                from .org_pilot import cmd_org_pilot
                return cmd_org_pilot(cfg,args)
            if args.org_action == 'inventory':
                from .org_inventory import cmd_org_inventory
                return cmd_org_inventory(cfg,args)
            if args.org_action == 'wave':
                from .org_wave import cmd_org_wave
                return cmd_org_wave(cfg,args)
            if args.org_action == 'reconcile':
                from .org_reconcile import cmd_org_reconcile
                return cmd_org_reconcile(cfg,args)
            if args.org_action == 'batch':
                from .org_bulk import cmd_org_bulk
                return cmd_org_bulk(cfg,args)
            if args.org_action == 'tail':
                from .org_tail import cmd_org_tail
                return cmd_org_tail(cfg,args)
            if args.org_action == 'infra':
                from .org_infra import cmd_org_infra
                return cmd_org_infra(cfg,args)
            if args.org_action == 'migrate':
                from .org_migrate import cmd_org_migrate
                return cmd_org_migrate(cfg,args)
            from .org import cmd_org_plan
            return cmd_org_plan(cfg,args)
        if args.action == 'persist':
            if not getattr(args,'plan',False) and not getattr(args,'audit',False):
                raise ArdaError('GitHub org migration in progress: source publishing is temporarily disabled until owner-aware persist and manifest policy are verified; use --plan or --audit')
            from .persist_plan import cmd_persist
            return cmd_persist(cfg, args)
        if args.action == 'track':
            from .build import cmd_track
            return cmd_track(cfg, args.module)
        if args.action == 'build':
            from .build import cmd_build
            return cmd_build(cfg, args.module, plan=args.plan, sync=args.sync, jobs=args.jobs)
        if args.action == 'test':
            from .deploy import cmd_test
            return cmd_test(cfg, args)
        if args.action == 'verify':
            from .deploy import cmd_verify
            return cmd_verify(cfg, args.module)
        if args.action == 'index': return cmd_index(cfg, args)
        if args.action == 'info': return cmd_info(cfg, args)
        if args.action == 'status': return cmd_status(cfg, args)
        if args.action == 'doctor': return cmd_doctor(cfg, args)
        if args.action in ('pull', 'diff'): return cmd_copy(cfg, args)
        return 2
    except (ArdaError, ValueError, OSError) as exc:
        print('ARDA_STOP=' + str(exc), file=sys.stderr)
        return 2
