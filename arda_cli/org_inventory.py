"""Read-only Mac controller for repository-by-repository org migration inventory."""
from __future__ import annotations
import datetime as dt, json, re, subprocess, zipfile
from .config import PACKAGE_ROOT


def cmd_org_inventory(cfg,args):
    from .cli import ArdaError, ssh_flags, format_table
    target=args.target
    if not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?',target):
        raise ArdaError('Invalid org name')
    worker=(PACKAGE_ROOT/'arda_cli'/'org_inventory_worker.py').read_text('utf8')
    worker=worker.replace('payload=json.loads(sys.stdin.read())',
                          'payload=json.loads('+repr(json.dumps({'root':cfg['aosp_root'],'target':target}))+')')
    try:
        p=subprocess.run(['ssh','-T',*ssh_flags(cfg),cfg['ubuntu'],'python3','-'],
                         input=worker,encoding='utf8',capture_output=True,timeout=280,errors='replace')
    except (OSError,subprocess.TimeoutExpired):
        raise ArdaError('Ubuntu org inventory SSH failed/timed out; no changes') from None
    try:result=json.loads(p.stdout.strip())
    except (ValueError,TypeError):
        raise ArdaError('Unable to decode Ubuntu inventory; no changes') from None
    if p.returncode or result.get('status')!='READ_ONLY_INVENTORY':
        raise ArdaError('Organization inventory stopped: '+str(result.get('error','unknown failure')))
    rows=result['repositories']
    if args.json:
        print(json.dumps(result,sort_keys=True,indent=2,ensure_ascii=False))
    else:
        print('ARDA ORG REPOSITORY INVENTORY — READ ONLY')
        print('  Target:             '+target)
        print('  Ubuntu gh actor:    '+result['actor'])
        print('  Membership:         '+result['organization_membership'])
        print('  Remaining at source:'+str(result['source_remaining']))
        print('  Target present:     '+str(result['target_present']))
        print('  Unique repos:       '+str(result['total_distinct']))
        table=[]
        for x in rows:
            man=len(x['active_manifest_refs'])
            remote=len(x['git_remotes'])
            table.append((x['name'],x['stage'],x['visibility'],str(man),str(remote),x['category']))
        format_table(('REPO','LOCATION','VIS','ACTIVE XML','REMOTES','REVIEW CLASS'),table)
        print('  All transfer decisions require separate exact-repo approval.')
        print('  No GitHub transfer, Git remote edits, manifest writes, repo sync, build or push.')
        print('RESULT=READ_ONLY_INVENTORY')
    if args.report:
        cfg['reports'].mkdir(parents=True,exist_ok=True)
        out=cfg['reports']/('ARDA_CLI_V1_11_ORG_INVENTORY_'+dt.datetime.now(dt.timezone.utc).strftime('%Y%m%d_%H%M%S')+'.zip')
        with zipfile.ZipFile(out,'x',compression=zipfile.ZIP_DEFLATED) as f:
            f.writestr('inventory.json',json.dumps(result,indent=2,sort_keys=True,ensure_ascii=False)+'\n')
            f.writestr('README.txt','Read-only remote and manifest metadata. No GitHub or AOSP changes.\n')
        print('REPORT_ZIP='+str(out))
    return 0
