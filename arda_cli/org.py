"""Mac UI for GitHub organization migration preflight; no mutation."""
from __future__ import annotations
import json, re, subprocess, datetime, zipfile
from .config import PACKAGE_ROOT

def cmd_org_plan(cfg,args):
    from .cli import ArdaError, ssh_flags, format_table
    target=args.target
    if not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?',target):
        raise ArdaError('Invalid target org name')
    helper=(PACKAGE_ROOT/'arda_cli'/'org_probe.py').read_text('utf8')
    inp=json.dumps({'root':cfg['aosp_root'],'target':target})
    # python3 - receives helper via stdin; payload embedded as a constant in helper code.
    code=helper.replace("payload=json.loads(sys.stdin.read())","payload=json.loads("+repr(inp)+")")
    try:
        proc=subprocess.run(['ssh','-T',*ssh_flags(cfg),cfg['ubuntu'],'python3 -'],
                            input=code,text=True,capture_output=True,timeout=220,errors='replace')
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise ArdaError('Ubuntu organization audit unavailable: '+type(exc).__name__) from None
    try:result=json.loads(proc.stdout.strip())
    except ValueError:raise ArdaError('GitHub organization preflight unavailable (SSH/probe failed)') from None
    if proc.returncode or 'error' in result:
        raise ArdaError('Organization preflight stopped: '+str(result.get('error','remote failure')))
    if args.json:
        print(json.dumps(result,indent=2,ensure_ascii=False))
    else:
        print('ARDA GITHUB ORGANIZATION MIGRATION PLAN — READ ONLY')
        print('  Current owner: Deadknight')
        print('  Target:        '+result['target'])
        print('  Org status:    '+result['organization_state'])
        print('  Membership:    '+result['membership'])
        print('  Candidates:    '+str(result['candidate_count']))
        format_table(('REPOSITORY','VISIBILITY','CONFLICT'),[(x['name'],x['visibility'],
            'YES' if x['name'] in result['name_conflicts'] else '-') for x in result['source_repositories']])
        print('  Local manifest references: '+', '.join(result['local_manifest_files_referencing_source_owner']) if result['local_manifest_files_referencing_source_owner'] else '  Local manifest references: none found in .repo/local_manifests')
        if result['organization_state'] != 'EXISTS':
            print('  CAUTION: Public GitHub 404 does not prove the org name is available.')
        print('  AFTER transfer: update verified Git remotes, repo manifests, ARDA CLI owner allowlists, CI secrets & webhooks.')
        print('  No transfer, repository creation, commit, push or AOSP changes performed.')
        print('RESULT=ORG_PLAN_ONLY')
    if args.report:
        cfg['reports'].mkdir(parents=True,exist_ok=True)
        filename=cfg['reports']/('ARDA_CLI_V1_8_ORG_PLAN_'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d_%H%M%S')+'.zip')
        with zipfile.ZipFile(filename,'x',compression=zipfile.ZIP_DEFLATED) as z:
            z.writestr('organization-plan.json',json.dumps(result,indent=2,ensure_ascii=False)+'\n')
        print('REPORT_ZIP='+str(filename))
    return 0
