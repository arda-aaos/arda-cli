"""Guarded public GitHub organization transfer waves (independent or remote-linked).

Remote-linked phase permits ONE public repository per wave, only without manifest
references. The exact identified .repo/projects remote URLs are migrated only
AFTER GitHub's repository ID and default branch HEAD have been verified.
No automatic manifest edits, builds, repo sync or release publish.
"""
from __future__ import annotations
import datetime as dt
import json
import re
import zipfile
from pathlib import Path
from .org_pilot import run_probe as pilot_probe, state_path as pilot_path
from .org_migrate import worker as migrate_probe, atomic_json, plan_file, receipt_file
from .config import PACKAGE_ROOT

SAFE_NAME = re.compile(r'^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,78}[A-Za-z0-9])?$')
STATE = Path.home()/'.local/share/arda-cli-v1/org-waves'
MAX_PER_WAVE = 3
MAX_PLAN_AGE_HOURS = 24
PHASES = ('independent', 'remote')


def validate_name(value):
    return bool(isinstance(value,str) and SAFE_NAME.fullmatch(value) and '..' not in value
                and not value.startswith('.') and not value.endswith('.'))


def inventory_data(cfg,target,enrich_active_sha=False):
    """Same authenticated Ubuntu inventory as `arda org inventory` (no writes)."""
    from .cli import ArdaError, ssh_flags
    import subprocess
    worker=(PACKAGE_ROOT/'arda_cli'/'org_inventory_worker.py').read_text('utf8')
    payload=json.dumps({'root':cfg['aosp_root'],'target':target,**({'enrich_active_sha':True} if enrich_active_sha else {})})
    marker='payload=json.loads(sys.stdin.read())'
    if worker.count(marker)!=1:raise ArdaError('Inventory worker contract changed; no transfer')
    worker=worker.replace(marker,'payload=json.loads('+repr(payload)+')')
    try:
        p=subprocess.run(['ssh','-T',*ssh_flags(cfg),cfg['ubuntu'],'python3','-'],
            input=worker,encoding='utf8',capture_output=True,timeout=300,errors='replace')
    except (OSError,subprocess.TimeoutExpired):
        raise ArdaError('GitHub/AOSP inventory unavailable; no transfer') from None
    try:res=json.loads(p.stdout.strip())
    except (ValueError,TypeError):raise ArdaError('Inventory unreadable; no transfer') from None
    if p.returncode or res.get('status')!='READ_ONLY_INVENTORY':
        raise ArdaError('Inventory check failed; no transfer: '+str(res.get('error','unknown')))
    return res


def eligible(row, phase='independent'):
    """Classifications are a shortlist, NOT a statement of zero external dependencies."""
    from .org_pilot_worker import EXCLUDED
    if phase not in PHASES: return False
    wanted = 'INDEPENDENT_REVIEW' if phase=='independent' else 'LOCAL_REMOTE_REVIEW'
    refs = row.get('git_remotes', [])
    if phase == 'remote':
        # Only known, exact SOURCE-owned local AOSP Git config refs. None may
        # be already migrated or outside .repo/projects. Not a general repair tool.
        if not isinstance(refs,list) or not refs: return False
        for rec in refs:
            if not isinstance(rec,dict) or rec.get('owner')!='SOURCE': return False
            fp=rec.get('file','')
            key=rec.get('remote','')
            if not isinstance(fp,str) or not fp.startswith('.repo/projects/') or not fp.endswith('/config'):
                return False
            if not isinstance(key,str) or re.fullmatch(r'remote\.[A-Za-z0-9_.-]+\.url',key) is None:
                return False
    return (row.get('stage')=='AT_SOURCE' and row.get('category')==wanted
            and row.get('visibility')=='PUBLIC' and row.get('archived') is False
            and row.get('fork') is False and validate_name(row.get('name'))
            and row['name'] not in EXCLUDED and not row.get('active_manifest_refs')
            and not row.get('library_manifest_refs') and (phase=='remote' or not refs)
            and validate_name(row.get('branch')) and isinstance(row.get('head_sha'),str)
            and re.fullmatch(r'[0-9a-f]{40}',row['head_sha']) is not None)


def snapshot_row(row):
    """Only bounded, non-secret, immutable decision fields for drift checking."""
    return {x:row.get(x) for x in ('name','stage','category','visibility','archived',
                                     'fork','branch','head_sha','active_manifest_refs',
                                     'library_manifest_refs','git_remotes')}


def plan_summary(inv, phase='independent'):
    rows=inv['repositories']
    return {
        'phase':phase,
        'target':inv['target'],
        'source_remaining':inv['source_remaining'],
        'transferred':sum(x['stage']=='TRANSFERRED' for x in rows),
        'candidates':[snapshot_row(r) for r in rows if eligible(r,phase)],
        'holds':[{'name':r['name'],'category':r['category'],'visibility':r['visibility']}
                 for r in rows if r['stage']=='AT_SOURCE' and not eligible(r,phase)],
        'notes':[
            'Independent classification is not proof of zero CI/release references.',
            'Only exact named repos with explicit confirmation can transfer; independent max 3, remote-linked max 1.',
            'Remote-linked phase changes matched Ubuntu .repo/projects remote URLs only; source and manifests remain untouched.',
            'Active AOSP manifest projects, private, archived, fork, vendor/device, manifest and release repositories are blocked.',
            'No `repo sync`, build, APK deployment, source commit or manifest rewrite.',
            'On partial success, stop; inspect journal and GitHub before any new transfer.'
        ]
    }


def snapshot_path(target, phase='independent'):
    return STATE/('plan_'+target+('_remote' if phase=='remote' else '')+'.json')


def _utcnow():return dt.datetime.now(dt.timezone.utc)


def _save(path, data):atomic_json(path,data)


def plan(cfg,target,phase='independent'):
    inv=inventory_data(cfg,target)
    if phase not in PHASES:raise ValueError('Invalid wave phase')
    summ=plan_summary(inv,phase)
    snap={'created_utc':_utcnow().isoformat(),'status':'PLAN_ONLY','summary':summ}
    _save(snapshot_path(target,phase),snap)
    return snap


def _load_apply_snapshot(cfg,target,repos,confirm,inv,phase='independent'):
    from .cli import ArdaError
    expected_confirm='TRANSFER '+','.join(repos)+' TO '+target
    if confirm!=expected_confirm:
        raise ArdaError('Exact --confirm required: '+expected_confirm)
    fp=snapshot_path(target,phase)
    if not fp.is_file():raise ArdaError('Run `arda org wave --plan` first; no transfer')
    try:snap=json.loads(fp.read_text('utf8'))
    except (OSError,ValueError):raise ArdaError('Invalid wave plan snapshot; no transfer') from None
    try:stamp=dt.datetime.fromisoformat(snap['created_utc'])
    except (TypeError,ValueError,KeyError):raise ArdaError('Plan timestamp missing') from None
    if stamp.tzinfo is None or not (0<=(_utcnow()-stamp).total_seconds()<=MAX_PLAN_AGE_HOURS*3600):
        raise ArdaError('Wave plan expired; run --plan again')
    if snap.get('summary',{}).get('target')!=target or snap['summary'].get('phase')!=phase:
        raise ArdaError('Wave plan target/phase mismatch')
    prior={r['name']:r for r in snap['summary']['candidates']}
    current={r['name']:r for r in inv['repositories']}
    for name in repos:
        if name not in prior:raise ArdaError(name+' not in approved independent public shortlist; no transfer')
        if name not in current or not eligible(current[name],phase):raise ArdaError(name+' no longer eligible; no transfer')
        if prior[name]!=snapshot_row(current[name]):raise ArdaError(name+' changed since wave plan; no transfer')
    return snap


def _one(cfg,repo,target,row,record,save):
    """No retry after an API transfer request. Each step has a restartable receipt."""
    from .cli import ArdaError
    payload={'repo':repo,'target':target,'root':cfg['aosp_root'],'apply':False,
             'expected':None,'confirm':''}
    pre=pilot_probe(cfg,payload)
    if pre.get('status')!='PLAN_ONLY':raise ArdaError('Pilot preflight stopped for '+repo)
    pilot=pre.get('preflight',{})
    if (pilot.get('decision')!='READY_PILOT' or pilot.get('source_head')!=row['head_sha']
            or pilot.get('default_branch')!=row['branch'] or pilot.get('visibility')!='public'
            or pilot.get('private') is not False or pilot.get('fork') is not False):
        raise ArdaError('Pilot metadata differs from wave inventory for '+repo)
    # The existing standalone `arda org migrate` can recover a partially moved repo.
    _save(pilot_path(repo,target),pilot)
    record.update(status='PREFLIGHT_PASS',original_head=pilot['source_head'],
                  repository_id=pilot['repository_id'])
    payload.update(apply=True,expected=pilot,
                   confirm='Deadknight/'+repo+' -> '+target+'/'+repo)
    # IMPORTANT: journal is updated BEFORE an external transfer request.
    record['status']='TRANSFER_REQUEST_MAY_BE_SENT'
    save()
    result=pilot_probe(cfg,payload)
    record['transfer_status']=result.get('status','UNKNOWN')
    if result.get('status')!='TRANSFER_VERIFIED':
        raise ArdaError(repo+' transfer not verified ('+str(result.get('status'))+
                        '); inspect GitHub; DO NOT retry automatically')
    record['status']='TRANSFER_VERIFIED'
    save()
    mig={'root':cfg['aosp_root'],'repo':repo,'target':target,'pilot':pilot,
         'apply':False,'confirm':'','snapshot':None}
    mp=migrate_probe(cfg,mig)
    if mp.get('status')!='READY_LOCAL_MIGRATION':
        record['migration_status']=mp.get('status','UNKNOWN')
        raise ArdaError(repo+' transferred, but local migration HOLD; inspect manifest/remotes')
    _save(plan_file(repo,target),mp)
    record['status']='MIGRATION_READY'
    mig.update(apply=True,snapshot=mp,
               confirm='Deadknight/'+repo+' -> '+target+'/'+repo)
    record['status']='MIGRATION_APPLY_MAY_HAVE_STARTED'
    save()
    after=migrate_probe(cfg,mig)
    record['migration_status']=after.get('status','UNKNOWN')
    if after.get('status')!='LOCAL_MIGRATION_VERIFIED':
        raise ArdaError(repo+' transferred; local migration not verified. Inspect Ubuntu remotes')
    github=after['verified_github']
    receipt={'source':'Deadknight/'+repo,'target':target+'/'+repo,
             'repository_id':github['repo_id'],'head_sha':github['head_sha'],
             'branch':github['branch'],'changed_remote_count':after.get('changed_remote_count',0),
             'scope':after.get('scope'),'updated_at_utc':_utcnow().isoformat(),
             'status':after['status']}
    _save(receipt_file(repo,target),receipt)
    record.update(status='COMPLETE',updated_remotes=receipt['changed_remote_count'],
                  verified_head=receipt['head_sha'])


def apply(cfg,target,repos,confirm,phase='independent'):
    from .cli import ArdaError
    if phase not in PHASES:raise ArdaError('Invalid wave phase')
    max_selected=1 if phase=='remote' else MAX_PER_WAVE
    if not repos or len(repos)>max_selected or len(set(repos))!=len(repos):
        raise ArdaError('Select 1..'+str(max_selected)+' distinct repositories with repeated --repo options')
    if any(not validate_name(x) for x in repos):raise ArdaError('Invalid repository name')
    journal_file=STATE/('wave_'+_utcnow().strftime('%Y%m%dT%H%M%S%fZ')+'.json')
    # We only inspect the state once before transfers; subsequent repo validations
    # use their own live GitHub API metadata and the original snapshot.
    # Validate the literal user confirmation before any network-dependent preflight.
    if confirm!='TRANSFER '+','.join(repos)+' TO '+target:
        raise ArdaError('Exact --confirm does not match selected repositories; no transfer')
    inv=inventory_data(cfg,target)
    _load_apply_snapshot(cfg,target,repos,confirm,inv,phase)
    rows={r['name']:r for r in inv['repositories']}
    journal={'started_utc':_utcnow().isoformat(),'target':target,
             'requested':repos,'phase':phase,'status':'IN_PROGRESS',
             'repos':[{'repo':x,'status':'NOT_STARTED'} for x in repos]}
    _save(journal_file,journal)
    try:
        for record in journal['repos']:
            name=record['repo']
            # write-before-transfer: transfer attempts can succeed even when SSH drops.
            record['status']='CHECKING'
            _save(journal_file,journal)
            try:
                _one(cfg,name,target,rows[name],record,lambda: _save(journal_file,journal))
            finally:
                _save(journal_file,journal)
        journal['status']='COMPLETE'
    except Exception as exc:
        journal['status']='STOP_PARTIAL_POSSIBLE'
        journal['error']=str(exc)[:350]
    finally:
        journal['completed_utc']=_utcnow().isoformat()
        _save(journal_file,journal)
    return journal,journal_file


def cmd_org_wave(cfg,args):
    from .cli import ArdaError
    target=args.target
    phase=getattr(args,'phase','independent')
    if phase not in PHASES:raise ArdaError('Invalid wave phase')
    if not validate_name(target) or target.casefold()=='deadknight':raise ArdaError('Invalid organization name')
    if args.apply and args.plan:
        raise ArdaError('Choose either --plan or --apply, not both')
    if args.apply:
        result,journal_path=apply(cfg,target,args.repo,args.confirm,phase)
        status=result['status']
        print('ARDA ORG WAVE — '+phase.upper()+' — EXPLICIT TRANSFER + LOCAL MIGRATION')
        for rec in result['repos']:
            print('  '+rec['repo']+': '+rec['status'])
        print('  Status: '+status)
        if status!='COMPLETE':
            print('  STOP: '+str(result.get('error','inspect receipt and GitHub')))
            print('  Do not rerun an ambiguous transfer; inspect GitHub and run standalone `arda org migrate` if needed.')
        print('  JOURNAL='+str(journal_path))
        print('  No AOSP manifest rewrite, repo sync, build, APK install, reboot or source push.')
    else:
        if args.repo:raise ArdaError('Use --repo only with --apply; plan always inventories full shortlist')
        result=plan(cfg,target,phase)
        summ=result['summary']
        status='PLAN_ONLY'
        print('ARDA ORG WAVE — READ ONLY')
        print('  Target: '+target)
        print('  Phase: '+phase)
        print('  Transferred: '+str(summ['transferred'])+'; at source: '+str(summ['source_remaining']))
        print('  '+('Remote-linked' if phase=='remote' else 'Independent')+' public shortlist: '+str(len(summ['candidates'])))
        for row in summ['candidates']:
            print('    '+row['name']+' ['+row['branch']+' '+row['head_sha'][:12]+']')
            if phase=='remote':
                for rec in row['git_remotes']:
                    print('      REMOTE '+rec['file']+' ['+rec['remote']+']')
        print('  Held for separate review: '+str(len(summ['holds'])))
        for row in summ['holds']:
            print('    HOLD '+row['name']+' ('+row['category']+')')
        print('  No GitHub transfer or Ubuntu writes. Plan expires after 24 hours.')
        if phase=='remote':
            print('  APPLY LIMIT: 1 explicit repo, verified Git remote migration; active manifest/private blocked.')
        print('RESULT=ORG_WAVE_PLAN_ONLY')
    if args.report:
        cfg['reports'].mkdir(parents=True,exist_ok=True)
        report=cfg['reports']/('ARDA_CLI_V1_13_ORG_WAVE_'+_utcnow().strftime('%Y%m%d_%H%M%S_%f')+'.zip')
        with zipfile.ZipFile(report,'x',compression=zipfile.ZIP_DEFLATED) as z:
            z.writestr('wave-result.json',json.dumps(result,indent=2,ensure_ascii=False,sort_keys=True)+'\n')
            z.writestr('README.txt','Plan is read-only; apply restricted to explicitly selected public repos in the chosen phase.\n'
                       'Any stopped transfer may have completed remotely; inspect before retry.\n')
        print('REPORT_ZIP='+str(report))
    return 0 if status in ('PLAN_ONLY','COMPLETE') else 4
