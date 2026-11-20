"""Mac-origin ArdaPlatform commit transfer to Ubuntu GitHub publisher.

Only already committed, clean Mac source may be sent. On Ubuntu it goes into
an ephemeral checkout. Never copies private signing files or uses direct Mac
GitHub credentials. Requires exact Deadknight main SHA, no force-push.
"""
from __future__ import annotations
import base64
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import zipfile

from .config import PACKAGE_ROOT

EXPECTED_REPO = 'arda-aaos/ArdaPlatform'
EXPECTED_URL = 'https://github.com/arda-aaos/ArdaPlatform.git'
SHA = re.compile(r'[0-9a-f]{40}\Z')
TMP = re.compile(r'/tmp/arda-mac-persist\.[A-Za-z0-9]{8,16}\Z')


def _git(root, *args, timeout=90):
    from .cli import ArdaError
    try:
        proc = subprocess.run(['git','-C',str(root),*args],capture_output=True,timeout=timeout,
                              stdin=subprocess.DEVNULL,text=True,encoding='utf8',errors='replace')
    except (OSError,subprocess.TimeoutExpired) as e:
        raise ArdaError('Mac Git operation failed: '+type(e).__name__) from None
    if proc.returncode:
        raise ArdaError('Mac Git operation rejected: '+args[0])
    return proc.stdout.strip()


def _ssh(cfg, remote_command, timeout=120, input_text=None):
    from .cli import ArdaError, ssh_flags
    p=subprocess.run(['ssh','-T',*ssh_flags(cfg),cfg['ubuntu'],remote_command],
                     input=input_text,capture_output=True,text=True,timeout=timeout,
                     encoding='utf8',errors='replace')
    if p.returncode:
        raise ArdaError('Ubuntu SSH operation rejected (details redacted)')
    return p.stdout.strip()


def validate_mac(cfg):
    from .cli import ArdaError
    root=cfg['platform'].resolve()
    if not root.is_dir():raise ArdaError('Configured ArdaPlatform Mac source does not exist')
    if Path(_git(root,'rev-parse','--show-toplevel')).resolve()!=root:
        raise ArdaError('Configured ArdaPlatform path must be exact Git root')
    current=_git(root,'rev-parse','HEAD')
    if not SHA.fullmatch(current):raise ArdaError('Mac HEAD is not a valid SHA')
    branch=_git(root,'symbolic-ref','--short','HEAD')
    if branch!='main':raise ArdaError('Only the ArdaPlatform main branch may be published')
    remotes=_git(root,'remote').splitlines()
    accepted=[]
    for name in remotes:
        url=_git(root,'remote','get-url',name)
        if url.rstrip('/').removesuffix('.git') in (EXPECTED_URL.removesuffix('.git'), 'git@github.com:arda-aaos/ArdaPlatform'):
            accepted.append(name)
    if len(accepted)!=1:raise ArdaError('Exactly one verified arda-aaos/ArdaPlatform remote required')
    raw=subprocess.run(['git','-C',str(root),'status','--porcelain=v1','-z','--untracked-files=all'],
                        capture_output=True,timeout=60)
    if raw.returncode:raise ArdaError('Unable to inspect Mac source changes')
    if raw.stdout:raise ArdaError('Mac ArdaPlatform source is not clean; review/commit changes explicitly before persist')
    return root,current


def remote_sha(cfg):
    from .cli import ArdaError
    cmd='git ls-remote --heads '+shlex.quote(EXPECTED_URL)+' refs/heads/main'
    output=_ssh(cfg,cmd,timeout=100)
    rows=output.splitlines()
    if len(rows)!=1 or not rows[0].endswith('\trefs/heads/main'):
        raise ArdaError('GitHub main SHA could not be uniquely verified')
    sha=rows[0].split('\t',1)[0]
    if not SHA.fullmatch(sha):raise ArdaError('Invalid GitHub main SHA')
    return sha


def mac_publish(cfg):
    from .cli import ArdaError, ssh_flags
    import os
    approved=os.environ.get('ARDA_PERSIST_APPROVED_MANIFEST_HEAD','')
    if not SHA.fullmatch(approved) or approved=='a85ead3d1d0973e73d7ff34a0cd2d1d67f1ceb0f':
        raise ArdaError('Owner-aware persist HOLD: approved new manifest SHA missing')
    if not cfg['ssh_key'].is_file():raise ArdaError('Ubuntu SSH key not found')
    root,head=validate_mac(cfg)
    base=remote_sha(cfg)
    if subprocess.run(['git','-C',str(root),'merge-base','--is-ancestor',base,head],
                      capture_output=True,timeout=45).returncode:
        raise ArdaError('GitHub main is not an ancestor of Mac ArdaPlatform HEAD; do not force push')
    with tempfile.TemporaryDirectory(prefix='arda-mac-bundle-') as temp:
        bundle=Path(temp)/'source.bundle'
        destination=None
        if head!=base:
            # A self-contained incremental bundle with the old remote head as prerequisite.
            _git(root,'bundle','create',str(bundle),'HEAD','^'+base,timeout=120)
            if not bundle.is_file() or bundle.stat().st_size>150_000_000:
                raise ArdaError('Git bundle missing/oversized')
        # Create controlled private Ubuntu temporary path; no sudo or repository writes.
        destination=_ssh(cfg,'mktemp -d /tmp/arda-mac-persist.XXXXXXXXXX',timeout=35)
        if not TMP.fullmatch(destination):raise ArdaError('Unsafe Ubuntu temporary directory')
        report_file=cfg['reports']/('ARDA_CLI_V1_8_PERSIST_ArdaPlatform_'+datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')+'.zip')
        if report_file.exists():raise ArdaError('Report ZIP exists; refusing overwrite')
        cfg['reports'].mkdir(parents=True,exist_ok=True)
        status=125; outcome=None
        try:
            if head!=base:
                upload=subprocess.run(['scp',*ssh_flags(cfg),str(bundle),
                                       cfg['ubuntu']+':'+destination+'/source.bundle'],
                                      capture_output=True,timeout=160)
                if upload.returncode:raise ArdaError('Unable to transfer Git bundle to Ubuntu')
            payload={'module':'ArdaPlatform','strategy':'DIRECT','expected_head':head,
                     'remote_base':base,'bundle_path':destination+'/source.bundle' if head!=base else None,
                     'approved_manifest_head':approved}
            encoded=base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
            helper=(PACKAGE_ROOT/'arda_cli'/'persist_worker.py').read_text('utf8')
            with tempfile.TemporaryDirectory(prefix='arda-mac-report-') as localtemp:
                logfile=Path(localtemp)/'publish.log'
                with logfile.open('w',encoding='utf8') as log:
                    p=subprocess.Popen(['ssh','-T',*ssh_flags(cfg),cfg['ubuntu'],
                                        'python3 - '+shlex.quote(encoded)],
                                       stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT,text=True,encoding='utf8',errors='replace',bufsize=1)
                    p.stdin.write(helper);p.stdin.close()
                    for line in p.stdout:
                        print(line,end='',flush=True)
                        log.write(line)
                        if line.startswith('ARDA_PERSIST_RESULT_JSON='):
                            try:outcome=json.loads(line.split('=',1)[1])
                            except ValueError:pass
                    status=p.wait(timeout=1200)
                summary={'module':'ArdaPlatform','source_head':head,'remote_before':base,
                         'worker_exit':status,'result':outcome,'source_only_not_build_attested':True,
                         'partial_push_possible':status!=0}
                with zipfile.ZipFile(report_file,'x',compression=zipfile.ZIP_DEFLATED) as z:
                    z.writestr('SUMMARY.json',json.dumps(summary,indent=2)+'\n')
                    z.write(logfile,'publish.log')
        finally:
            # Remote temp cleanup is never allowed to hide source publication result.
            try:_ssh(cfg,'rm -f '+shlex.quote(destination+'/source.bundle')+' && rmdir '+shlex.quote(destination),timeout=30)
            except Exception:print('WARNING=Ubuntu temporary bundle may require cleanup')
        print('REPORT_ZIP='+str(report_file))
        if status==0 and outcome and outcome.get('status') in ('PASS_PUBLISHED','NO_NEW_SOURCE_CHANGES'):
            print('RESULT='+outcome['status'])
            return 0
        print('RESULT=STOP_PERSIST_PARTIAL_STATE_POSSIBLE')
        return 3
