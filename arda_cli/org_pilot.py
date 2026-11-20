"""Mac controller for explicit one-repo GitHub transfer; snapshot + report."""
from __future__ import annotations
import datetime, json, re, subprocess, zipfile
from pathlib import Path
from .config import PACKAGE_ROOT

def state_path(repo,target):
    return Path.home()/'.local/share/arda-cli-v1/org-pilot-plans'/(target+'__'+repo+'.json')

def run_probe(cfg,payload):
    from .cli import ArdaError, ssh_flags
    script=(PACKAGE_ROOT/'arda_cli'/'org_pilot_worker.py').read_text('utf8')
    # No secrets sent. Source code and payload are both stdin, with a single controlled replacement.
    script=script.replace('payload=json.loads(sys.stdin.read())','payload=json.loads('+repr(json.dumps(payload))+')')
    try:
        p=subprocess.run(['ssh','-T',*ssh_flags(cfg),cfg['ubuntu'],'python3 -'],input=script,
                         capture_output=True,text=True,errors='replace',timeout=240)
    except (OSError,subprocess.TimeoutExpired):
        raise ArdaError('Ubuntu GitHub pilot unavailable; no automatic retry') from None
    try:
        result=json.loads(p.stdout.strip())
    except ValueError:
        raise ArdaError('Unable to read pilot result; check GitHub before retrying transfer') from None
    if not isinstance(result,dict):raise ArdaError('Invalid pilot result')
    if p.returncode and result.get('status')!='STOP':raise ArdaError('Pilot SSH returned failure')
    return result

def cmd_org_pilot(cfg,args):
    from .cli import ArdaError
    for name in (args.repo,args.target):
        if not isinstance(name,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,78}[A-Za-z0-9]|[A-Za-z0-9]',name) or '..' in name:
            raise ArdaError('Invalid owner or repo name')
    saved=state_path(args.repo,args.target)
    expected=None
    if args.apply:
        if not saved.is_file():raise ArdaError('Run pilot --plan first; no transfer')
        expected=json.loads(saved.read_text('utf8'))
    payload={'repo':args.repo,'target':args.target,'root':cfg['aosp_root'],
             'apply':args.apply,'expected':expected,'confirm':args.confirm}
    result=run_probe(cfg,payload)
    if result.get('status')=='STOP':
        print('ARDA_ORG_PILOT_STOP='+str(result.get('error','Unknown preflight failure')))
    else:
        base=result.get('preflight',{})
        print('ARDA ORG PILOT'+(' — TRANSFER REQUEST' if args.apply else ' — READ ONLY'))
        print('  Source:       '+str(base.get('source')))
        print('  Target:       '+str(base.get('target')))
        print('  Repo ID:      '+str(base.get('repository_id')))
        print('  HEAD:         '+str(base.get('source_head')))
        print('  Visibility:   '+str(base.get('visibility')))
        print('  Branch:       '+str(base.get('default_branch')))
        print('  Status:       '+str(result.get('status')))
        if args.apply:
            print('  No repo sync, source writes, build, manifest edits or force push performed.')
            print('  Remote URLs/CLI owner rules will need a separate verified migration.')
        else:
            saved.parent.mkdir(parents=True,exist_ok=True)
            saved.write_text(json.dumps(base,indent=2,sort_keys=True)+'\n','utf8')
            print('  PLAN_SNAPSHOT='+str(saved))
            print('  No transfer performed. To transfer explicitly, pass --apply and exact --confirm string.')
    if args.report:
        cfg['reports'].mkdir(parents=True,exist_ok=True)
        fname=cfg['reports']/('ARDA_CLI_V1_9_ORG_PILOT_'+datetime.datetime.now().strftime('%Y%m%d_%H%M%S')+'.zip')
        with zipfile.ZipFile(fname,'x',compression=zipfile.ZIP_DEFLATED) as z:
            z.writestr('pilot-result.json',json.dumps(result,indent=2,sort_keys=True)+'\n')
        print('REPORT_ZIP='+str(fname))
    if result.get('status')=='STOP':return 2
    if result.get('status') in ('REQUEST_ACCEPTED_VERIFICATION_PENDING','REQUEST_OUTCOME_UNKNOWN_CHECK_GITHUB'):return 4
    return 0
