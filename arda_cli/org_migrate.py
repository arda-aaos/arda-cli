"""Mac controller: migration of local Git references after a VERIFIED pilot transfer."""
from __future__ import annotations
import datetime as dt, json, os, re, subprocess, zipfile
from pathlib import Path
from .config import PACKAGE_ROOT
from .org_pilot import state_path as original_pilot_path

NAME=re.compile(r'^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,78}[A-Za-z0-9])?$')
STATE=Path.home()/'.local/share/arda-cli-v1/org-migration'

def plan_file(repo,target):
    return STATE/'plans'/(target+'__'+repo+'.json')

def receipt_file(repo,target):
    return STATE/'receipts'/(target+'__'+repo+'.json')

def worker(cfg,payload):
    from .cli import ArdaError, ssh_flags
    code=(PACKAGE_ROOT/'arda_cli'/'org_migrate_worker.py').read_text('utf8')
    source=code.replace('payload=json.loads(sys.stdin.read())', 'payload=json.loads('+repr(json.dumps(payload))+')')
    try:
        p=subprocess.run(['ssh','-T',*ssh_flags(cfg),cfg['ubuntu'],'python3','-'],input=source,
                         capture_output=True,text=True,timeout=240,errors='replace')
    except (OSError,subprocess.TimeoutExpired):
        raise ArdaError('Migration SSH failed or timed out; inspect Ubuntu before retrying --apply') from None
    try: result=json.loads(p.stdout.strip())
    except (ValueError,TypeError):
        raise ArdaError('Migration result unreadable; inspect Ubuntu Git remotes before retrying') from None
    if not isinstance(result,dict):raise ArdaError('Malformed migration response')
    if p.returncode and result.get('status')!='STOP':raise ArdaError('Ubuntu migration execution failed')
    return result

def atomic_json(path,obj):
    path.parent.mkdir(parents=True,exist_ok=True)
    tmp=path.with_name(path.name+'.'+str(os.getpid())+'.tmp')
    try:
        with tmp.open('x',encoding='utf8') as f:
            json.dump(obj,f,indent=2,ensure_ascii=False,sort_keys=True)
            f.write('\n');f.flush();os.fsync(f.fileno())
        os.replace(tmp,path)
    finally:
        tmp.unlink(missing_ok=True)

def cmd_org_migrate(cfg,args):
    from .cli import ArdaError
    for name in (args.repo,args.target):
        if not NAME.fullmatch(name) or '..' in name:raise ArdaError('Invalid migration name')
    orig=original_pilot_path(args.repo,args.target)
    if not orig.is_file():
        raise ArdaError('Original pilot snapshot missing; cannot trust a post-transfer redirect. No changes.')
    try:pilot=json.loads(orig.read_text('utf8'))
    except (OSError,ValueError):raise ArdaError('Original pilot snapshot unreadable') from None
    snapfile=plan_file(args.repo,args.target)
    snap=None
    if args.apply:
        if not snapfile.is_file():raise ArdaError('Run arda org migrate --plan first; no changes')
        try:snap=json.loads(snapfile.read_text('utf8'))
        except (OSError,ValueError):raise ArdaError('Migration snapshot unreadable') from None
    payload={'root':cfg['aosp_root'],'repo':args.repo,'target':args.target,
             'pilot':pilot,'apply':args.apply,'confirm':args.confirm,'snapshot':snap}
    result=worker(cfg,payload)
    status=result.get('status')
    print('ARDA ORG LOCAL MIGRATION'+(' — APPLY' if args.apply else ' — PLAN / READ ONLY'))
    print('  Source:       Deadknight/'+args.repo)
    print('  Target:       '+args.target+'/'+args.repo)
    print('  Status:       '+str(status))
    v=result.get('verified_github',{})
    if v:
        print('  GitHub ID:    '+str(v.get('repo_id')))
        print('  Git HEAD:     '+str(v.get('head_sha')))
        print('  Git branch:   '+str(v.get('branch')))
    print('  Git remotes:  '+str(len(result.get('remotes',[])))+' matching in AOSP .repo configs')
    for rec in result.get('remotes',[]):
        print('    '+rec['state']+' '+rec['config']+' ['+rec['remote']+']')
    print('  Manifest refs: '+str(len(result.get('manifest_refs',[]))))
    for x in result.get('manifest_refs',[]):print('    HOLD: '+x)
    for x in result.get('ambiguous_remote_refs',[]):print('    HOLD: ambiguous Git URL in '+x['config'])
    if not args.apply and status=='READY_LOCAL_MIGRATION':
        atomic_json(snapfile,result)
        print('  PLAN_SNAPSHOT='+str(snapfile))
        print('  No changes made; use --apply --confirm with the exact source/target pair.')
    elif args.apply and status=='LOCAL_MIGRATION_VERIFIED':
        # Registry is NOT blanket authorization for other organization repos.
        receipt={'source':'Deadknight/'+args.repo,'target':args.target+'/'+args.repo,
                 'repository_id':v['repo_id'],'head_sha':v['head_sha'],'branch':v['branch'],
                 'changed_remote_count':result.get('changed_remote_count',0),
                 'scope':result.get('scope'),'updated_at_utc':dt.datetime.now(dt.timezone.utc).isoformat(),
                 'status':status}
        atomic_json(receipt_file(args.repo,args.target),receipt)
        print('  Updated remotes: '+str(result.get('changed_remote_count',0)))
        print('  RECEIPT='+str(receipt_file(args.repo,args.target)))
        print('  Other repos/CI/manifest pins were NOT modified.')
    else:
        print('  No GitHub transfer, source build, repo sync, manifest rewrite or push performed.')
    if args.report:
        cfg['reports'].mkdir(parents=True,exist_ok=True)
        f=cfg['reports']/('ARDA_CLI_V1_10_ORG_MIGRATE_'+dt.datetime.now(dt.timezone.utc).strftime('%Y%m%d_%H%M%S')+'.zip')
        with zipfile.ZipFile(f,'x',compression=zipfile.ZIP_DEFLATED) as z:
            z.writestr('migration-result.json',json.dumps(result,ensure_ascii=False,sort_keys=True,indent=2)+'\n')
            z.writestr('migration-summary.txt','Source: Deadknight/'+args.repo+'\nTarget: '+args.target+'/'+args.repo+'\nStatus: '+str(status)+'\n')
        print('REPORT_ZIP='+str(f))
    return 0 if status in ('READY_LOCAL_MIGRATION','LOCAL_MIGRATION_VERIFIED') else 3
