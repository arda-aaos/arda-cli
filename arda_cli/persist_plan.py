"""V1.5 source-persistence planning; read-only, never commits, pushes or changes manifests.

This module reports what WOULD need checking before a separate implementation of
persist. It is not an approval token and does not attest that a GitHub SHA exists.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
from typing import Any

from .config import PROFILES, local_root
from .release_refs import RECORDS, RELEASE_MANIFEST_SHA

KEY_EXTENSIONS = {'.pk8', '.p12', '.pfx', '.jks', '.keystore', '.key', '.asc', '.gpg', '.kdbx'}
KEY_NAME = re.compile(r'(?:^|[/_.-])(?:private[_-]?key|release[_-]?key|signing[_-]?key|keystore)(?:$|[/_.-])', re.I)
BACKUP_COMPONENTS = {'.arda-backups', '.git', '.repo', 'build', 'out'}
HEX_SHA = re.compile(r'^[0-9a-f]{40}$')


def classify_changed_path(path: str) -> str:
    """Name-based triage only; does NOT validate file content or Git history."""
    parts = set(Path(path).parts)
    if 'signing' in parts or Path(path).suffix.lower() in KEY_EXTENSIONS or KEY_NAME.search(path):
        return 'SENSITIVE_PATH'
    if parts & BACKUP_COMPONENTS or path.endswith(('~', '.bak', '.orig', '.swp')):
        return 'BACKUP_OR_OUTPUT'
    return 'SOURCE'


def classify_changes(raw: list[dict]) -> dict:
    result: dict[str, Any] = {'source': 0, 'backup_or_output': 0, 'sensitive_path': 0,
                              'staged': 0, 'untracked': 0, 'total': len(raw), 'examples': []}
    for item in raw:
        path, code = item['path'], item['code']
        kind = ('BACKUP_OR_OUTPUT' if code=='??' and path.startswith('updater/signing/')
                else classify_changed_path(path))
        result[kind.lower()] += 1
        result['staged'] += int(code[0] not in (' ', '?'))
        result['untracked'] += int(code == '??')
        # For safety report only a limited number of normal source paths, never key paths.
        if kind == 'SOURCE' and len(result['examples']) < 6:
            result['examples'].append({'status': code, 'path': path})
    return result


def porcelain_status(root: Path) -> list[dict]:
    """Parse --porcelain=v1 -z without trimming leading status characters.

    This avoids the old V49 error where ' M Android.bp' lost its first column.
    """
    args = ['git', '-c', 'core.fsmonitor=false', '-c', 'core.untrackedCache=false',
            '-C', str(root), 'status', '--porcelain=v1', '-z', '--untracked-files=all']
    env = dict(os.environ, GIT_OPTIONAL_LOCKS='0', GIT_TERMINAL_PROMPT='0')
    process = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             timeout=70, env=env)
    if process.returncode:
        raise ValueError('Git status unavailable (read-only preflight stopped)')
    raw = process.stdout.decode('utf-8', errors='replace')
    if not raw:
        return []
    if not raw.endswith('\0'):
        raise ValueError('Incomplete Git porcelain output')
    entries = raw[:-1].split('\0')
    results = []
    i = 0
    while i < len(entries):
        entry = entries[i]
        if len(entry) < 4 or entry[2] != ' ':
            raise ValueError('Malformed Git porcelain record')
        status, path = entry[:2], entry[3:]
        if not path or path.startswith('/') or '..' in Path(path).parts:
            raise ValueError('Unsafe path reported by Git')
        if any(c in status for c in 'RC'):
            i += 1  # destination/source of rename/copy (Git -z output)
            if i >= len(entries):
                raise ValueError('Incomplete Git rename record')
        results.append({'code': status, 'path': path})
        i += 1
    return results


def mac_source_state(cfg: dict, module: str, source: str) -> dict:
    """Report whether Mac edits are present without moving any files."""
    if module not in PROFILES or not PROFILES[module]['source'] or not PROFILES[module]['pull']:
        return {'state': 'NOT_MANAGED_AS_MAC_PULL'}
    local = local_root(cfg, module)
    if not local.is_dir():
        return {'state': 'NO_LOCAL_COPY'}
    if module == 'DirectRenderingCluster':
        from .build import read_state, snapshot, changes
        baseline = read_state(cfg, module)
        if baseline is None:
            return {'state': 'UNTRACKED_BASELINE', 'warning': 'Local source exists but no common baseline is recorded'}
        now = snapshot(local)
        delta = changes(baseline['files'], now)
        changed = sum(map(len, delta.values()))
        return {'state': 'CHANGED_SINCE_BASELINE' if changed else 'BASELINE_UNCHANGED',
                'modified': len(delta['modified']), 'added': len(delta['new']),
                'deleted': len(delta['deleted']), 'files': len(now),
                'baseline_head': baseline.get('head')}
    return {'state': 'LOCAL_PRESENT_NOT_TRACKED',
            'warning': 'No proven sync baseline; local working copy cannot be certified'}


def decide(name: str, assessed: dict, counts: dict, mac: dict | None = None) -> dict:
    """Pure decision; conservative: a plan is never permission to publish."""
    strategy = assessed.get('strategy', 'UNMANAGED')
    record = assessed.get('release_record') or {}
    head = assessed.get('head')
    git_path = assessed.get('repo_path')
    flags = []
    if not assessed.get('git') or not HEX_SHA.fullmatch(head or ''):
        flags.append('SOURCE_GIT_UNAVAILABLE')
    if strategy == 'UNMANAGED':
        flags.append('STRATEGY_UNMANAGED')
    if counts['sensitive_path']:
        flags.append('SENSITIVE_PATH_REQUIRES_REVIEW')
    if counts['staged']:
        flags.append('INDEX_ALREADY_STAGED_REVIEW_REQUIRED')
    if counts['backup_or_output']:
        flags.append('BACKUPS_OR_OUTPUT_PRESENT_EXCLUDE_FROM_STAGING')
    if mac and mac.get('state') == 'CHANGED_SINCE_BASELINE':
        flags.append('MAC_EDITS_NOT_PERSISTED_IN_UBUNTU')
    if mac and mac.get('state') in ('UNTRACKED_BASELINE', 'LOCAL_PRESENT_NOT_TRACKED'):
        flags.append('MAC_PROVENANCE_NOT_VERIFIED')
    if mac and mac.get('baseline_head') and head and mac['baseline_head'] != head:
        flags.append('UBUNTU_HEAD_CHANGED_SINCE_MAC_BASELINE')
    if strategy == 'PATCH':
        base = (RECORDS.get(git_path) or {}).get('baseline')
        diff = assessed.get('base_diff') or {}
        if not base or diff.get('base') != base or diff.get('measured') is not True:
            flags.append('PATCH_UPSTREAM_BASE_NOT_VERIFIED')
    manifest = assessed.get('manifest') or {}
    rev = str(manifest.get('revision') or '')
    if strategy == 'PATCH':
        manifest_relation = 'UPSTREAM_PLUS_RELEASE_PATCH'
    elif not manifest:
        manifest_relation = 'NO_RESOLVED_LOCAL_MANIFEST'
    elif rev == head:
        manifest_relation = 'LOCAL_MANIFEST_HEAD_MATCH'
    elif HEX_SHA.fullmatch(rev):
        manifest_relation = 'LOCAL_MANIFEST_SHA_DIFFERS'
        flags.append('MANIFEST_SHA_NOT_CURRENT_LOCAL_HEAD')
    else:
        manifest_relation = 'LOCAL_MANIFEST_NOT_PINNED_SHA'
        flags.append('MANIFEST_PIN_NOT_PROVEN')
    blockers = {'SOURCE_GIT_UNAVAILABLE', 'STRATEGY_UNMANAGED', 'SENSITIVE_PATH_REQUIRES_REVIEW',
                'INDEX_ALREADY_STAGED_REVIEW_REQUIRED', 'MAC_EDITS_NOT_PERSISTED_IN_UBUNTU',
                'MAC_PROVENANCE_NOT_VERIFIED', 'UBUNTU_HEAD_CHANGED_SINCE_MAC_BASELINE',
                'PATCH_UPSTREAM_BASE_NOT_VERIFIED'}
    if any(f in blockers for f in flags):
        readiness = 'HOLD_FOR_REVIEW'
    elif counts['source'] or (assessed.get('release_status') == 'DIFFERS_FROM_RELEASE'):
        readiness = 'SOURCE_REVIEW_NEEDED'
    else:
        readiness = 'NO_NEW_SOURCE_CHANGES_DETECTED'
    tasks = ['Inspect changed source paths and existing Git index; never blanket-add the source tree',
             'Verify signing/private-key files, complete reachable Git history and new payloads',
             'Confirm destination remote and existing GitHub branch/SHA without force-push',
             'Build/test the exact source state separately before any release publication',
             'Create a NEW manifest checkpoint while preserving V49.7 and prior pins',
             'Verify GitHub remote SHAs and clean replay after publication']
    if strategy == 'PATCH':
        tasks.insert(0, 'Generate consolidated patch from the VERIFIED upstream base and validate clean replay/tree SHA')
    elif strategy in ('DIRECT', 'FORK'):
        tasks.insert(0, 'Prepare limited Git commit for the existing owned fork/repo; do not migrate strategy implicitly')
    else:
        tasks.insert(0, 'Resolve repository ownership before choosing fork/direct/patch strategy')
    return {'module': name, 'git_path': git_path, 'strategy': strategy,
            'release_status': assessed.get('release_status'), 'release_ref': record.get('release_head'),
            'head': head, 'manifest_relation': manifest_relation,
            'manifest_revision': rev or None, 'dirty': counts, 'mac': mac,
            'readiness': readiness, 'flags': flags, 'proposed_tasks': tasks,
            'manifest_reference': RELEASE_MANIFEST_SHA,
            'remote_sha_verified': False, 'private_key_history_audited': False,
            'source_replay_verified': False, 'no_actions_performed': True}


def _mac_strategy(cfg: dict, name: str) -> tuple[dict, dict]:
    from .cli import _local_mac_strategy, assess_strategy, _strategy_known, ArdaError
    raw = _local_mac_strategy(cfg, name, None)
    assessed = assess_strategy(raw, _strategy_known(name), mac_project=True)
    local = local_root(cfg, name)
    if not raw.get('git') or not local.is_dir():
        raise ArdaError('Mac project Git checkout unavailable')
    return assessed, classify_changes(porcelain_status(local))


def persist_one(cfg: dict, name: str) -> dict:
    """Fetch remote Git STATUS and manifest metadata through read-only SSH probe."""
    from .cli import _module_source, _strategy_known, assess_strategy, remote, ArdaError
    if name in PROFILES and PROFILES[name]['kind'] == 'mac-gradle':
        assessed, counts = _mac_strategy(cfg, name)
        result = decide(name, assessed, counts, mac={'state': 'MAC_PROJECT', 'note': 'Local Git tree only'})
        result['manifest_relation'] = 'MAC_PROJECT_NOT_IN_AOSP_MANIFEST'
        result['flags'] = [x for x in result['flags'] if x != 'MANIFEST_PIN_NOT_PROVEN']
        return result
    src = _module_source(cfg, name)
    record = _strategy_known(src)
    response = remote(cfg, 'persist_plan', source=src, base=record.get('baseline'))
    if not response.get('git'):
        raise ArdaError(f'Git source not available for {name}')
    known = _strategy_known(response.get('repo_path', ''))
    assessed = assess_strategy(response, known)
    if response.get('source_status') is None:
        raise ArdaError('Could not read Git status')
    counts = response['source_status']
    mac = mac_source_state(cfg, name, src)
    return decide(name, assessed, counts, mac)


def print_one(result: dict) -> None:
    print('ARDA PERSIST PLAN (READ-ONLY; NO PUSH)')
    rows = [
        ('Module', result['module']), ('Git project', result['git_path']),
        ('Strategy', result['strategy']), ('Current HEAD', result['head']),
        ('V49.7 reference', result['release_status']),
        ('Local manifest', result['manifest_relation']),
        ('Mac source state', (result.get('mac') or {}).get('state', 'NOT_APPLICABLE')),
        ('Changed source paths', result['dirty']['source']),
        ('Backups/output paths', result['dirty']['backup_or_output']),
        ('Sensitive-name paths', result['dirty']['sensitive_path']),
        ('Staged entries', result['dirty']['staged']),
        ('Decision', result['readiness']),
    ]
    for k, v in rows:
        print(f'  {k:23}: {v}')
    if result['flags']:
        print('  Notices:')
        for flag in result['flags']: print('    - ' + flag)
    print('  Proposed next steps (not executed):')
    for step in result['proposed_tasks']: print('    - ' + step)
    print('  REMOTE_SHA_VERIFIED=NO; SECRET_HISTORY_AUDITED=NO; CLEAN_REPLAY_VERIFIED=NO')
    print('RESULT=PLAN_ONLY_NO_CHANGES')


def cmd_persist(cfg: dict, args) -> int:
    from .cli import ArdaError, format_table, report
    if args.audit:
        if args.plan:
            raise ArdaError('Choose --plan or --audit, not both')
        from .persist_audit import cmd_audit
        return cmd_audit(cfg, args)
    if not args.plan:
        from .persist_publish import cmd_publish
        return cmd_publish(cfg, args)
    if args.all and args.module:
        raise ArdaError('Use either MODULE or --all')
    if not args.all and not args.module:
        raise ArdaError('Specify a module/project or --all')
    names = list(sorted(PROFILES)) if args.all else [args.module]
    results = [persist_one(cfg, name) for name in names]
    if args.json:
        print(json.dumps(results, indent=2, ensure_ascii=False))
    elif len(results) == 1:
        print_one(results[0])
    else:
        format_table(('MODULE', 'STRATEGY', 'SOURCE', 'BACKUPS', 'FLAGS', 'DECISION'),
                     [(x['module'], x['strategy'], str(x['dirty']['source']),
                       str(x['dirty']['backup_or_output']), str(len(x['flags'])), x['readiness'])
                      for x in results])
        print('No Git commit/push, manifest update, build or source sync performed.')
        print('RESULT=PLAN_ONLY_NO_CHANGES')
    if args.report:
        report(cfg, 'persist_plan', {'rows': results})
    return 0
