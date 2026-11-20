"""Guarded opt-in execution of ARDA source-only checkpoint publication.

Uses the preexisting V1.5 plan and V1.6 audit mechanisms for provenance.
Never attempts to promote Mac-only projects or unverified forks automatically.
"""
from __future__ import annotations
import base64
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import zipfile
from .config import PACKAGE_ROOT
from .persist_plan import persist_one

SUPPORTED = {'DirectRenderingCluster':'PATCH','CarSystemUI':'FORK','arda-connectivityd':'DIRECT'}
ALLOWED_FLAGS = {'BACKUPS_OR_OUTPUT_PRESENT_EXCLUDE_FROM_STAGING',
                 'MANIFEST_SHA_NOT_CURRENT_LOCAL_HEAD'}

def approve_publish(plan, name):
    """Pure safety gate. Does not authorize a publish by itself."""
    if name not in SUPPORTED:
        return 'NO_VERIFIED_PUBLISH_PROFILE'
    if plan['strategy'] != SUPPORTED[name]:
        return 'STRATEGY_MISMATCH'
    if (plan.get('readiness')=='NO_NEW_SOURCE_CHANGES_DETECTED'
            and plan.get('release_status')!='DIFFERS_FROM_RELEASE'
            and plan.get('manifest_relation')!='LOCAL_MANIFEST_SHA_DIFFERS'):
        return 'NO_CHANGES'
    disallowed=set(plan.get('flags') or [])-ALLOWED_FLAGS
    if disallowed:
        return 'BLOCKED_FLAGS='+','.join(sorted(disallowed))
    if plan['dirty']['staged'] or plan['dirty']['sensitive_path']:
        return 'INDEX_OR_SECRET_CHANGE_REQUIRES_MANUAL_REVIEW'
    if plan['dirty']['source']>500:
        return 'TOO_MANY_SOURCE_CHANGES'
    if not re.fullmatch(r'[0-9a-f]{40}',str(plan.get('head'))):
        return 'HEAD_NOT_VERIFIED'
    if plan.get('readiness') not in ('SOURCE_REVIEW_NEEDED','NO_NEW_SOURCE_CHANGES_DETECTED'):
        return 'PLAN_NOT_READY'
    return 'READY'


def cmd_publish(cfg, args):
    from .cli import ArdaError, ssh_flags
    if args.module=='ArdaPlatform' and not args.all:
        from .persist_mac import mac_publish
        return mac_publish(cfg)
    if args.all or not args.module: raise ArdaError('Publish requires exactly one managed module. --all is disallowed.')
    if args.json: raise ArdaError('--json is available for --plan/--audit; publish produces a ZIP report')
    module=args.module
    plan=persist_one(cfg,module)
    decision=approve_publish(plan,module)
    if decision=='NO_CHANGES':
        print('ARDA PERSIST SOURCE CHECK')
        print('  Module: '+module)
        print('  State:  No new source changes')
        print('  No Git commit, push, manifest update, build, install or reboot.')
        print('RESULT=NOTHING_TO_PERSIST')
        return 0
    if decision!='READY':
        raise ArdaError('Publish stopped by safety gate: '+decision+'; run `arda persist '+module+' --plan`')
    if not cfg['ssh_key'].is_file():raise ArdaError('Configured SSH key does not exist')
    approved=os.environ.get('ARDA_PERSIST_APPROVED_MANIFEST_HEAD','')
    if not re.fullmatch(r'[0-9a-f]{40}',approved) or approved=='a85ead3d1d0973e73d7ff34a0cd2d1d67f1ceb0f':
        raise ArdaError('Owner-aware persist HOLD: approved new manifest SHA missing')
    payload={'module':module,'strategy':plan['strategy'],
             'approved_manifest_head':approved,
             'expected_head':plan['head'], 'release_status':plan.get('release_status'),
             'root':cfg['aosp_root']}
    encoded=base64.urlsafe_b64encode(json.dumps(payload).encode()).decode('ascii')
    helper=(PACKAGE_ROOT/'arda_cli'/'persist_worker.py').read_text('utf8')
    target=cfg['ubuntu']
    cmdline='python3 - '+shlex.quote(encoded)
    timestamp=datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    cfg['reports'].mkdir(parents=True,exist_ok=True)
    output=cfg['reports']/f'ARDA_CLI_V1_8_PERSIST_{module}_{timestamp}.zip'
    if output.exists():raise ArdaError('Report output already exists')
    stdout_lines=[]; result=None; exitcode=125
    with tempfile.TemporaryDirectory(prefix='arda-persist-report-') as td:
        logfile=Path(td)/'publish.log'
        with logfile.open('w',encoding='utf8') as log:
            try:
                proc=subprocess.Popen(['ssh','-T',*ssh_flags(cfg),target,cmdline],
                     stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
                     text=True,bufsize=1,encoding='utf8',errors='replace')
                proc.stdin.write(helper)
                proc.stdin.close()
                for line in proc.stdout:
                    # Publisher never emits key contents or raw private repository data.
                    print(line,end='',flush=True)
                    log.write(line)
                    if line.startswith('ARDA_PERSIST_RESULT_JSON='):
                        try:result=json.loads(line.split('=',1)[1])
                        except ValueError:pass
                exitcode=proc.wait(timeout=1200)
            except (OSError,subprocess.TimeoutExpired) as exc:
                log.write('Runner error: '+type(exc).__name__+'\n')
        summary={'module':module,'requested':'persist','source_before':plan['head'],
                 'strategy':plan['strategy'],'runner_exit':exitcode,
                 'result':result,'source_only':True,
                 'note':'On interrupted source push, rerun only after inspecting remote and manifest SHA; no rollback is automatic.'}
        with zipfile.ZipFile(output,'x',compression=zipfile.ZIP_DEFLATED) as z:
            z.writestr('SUMMARY.json',json.dumps(summary,indent=2)+'\n')
            z.write(logfile,'publish.log')
    print('REPORT_ZIP='+str(output))
    if exitcode==0 and result and result.get('status') in ('PASS_PUBLISHED','NO_NEW_SOURCE_CHANGES'):
        print('RESULT='+result['status'])
        return 0
    print('RESULT=STOP_PERSIST_PARTIAL_STATE_POSSIBLE')
    return 3
