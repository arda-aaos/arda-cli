"""ARDA CLI V1.14 - public AOSP source transfer batch.

One frozen plan, complete read-only preflight, one guarded execution; no
implicit retry, no private repos, no manifest/source modifications.
"""
from __future__ import annotations
import datetime as dt, hashlib, json, os, re, subprocess, zipfile
from pathlib import Path
from .config import PACKAGE_ROOT
from .org_wave import inventory_data, validate_name
from .org_migrate import atomic_json

STATE=Path.home()/'.local/share/arda-cli-v1/org-batch'
MAX_AGE_HOURS=24
MAX_BATCH=12


def _now():return dt.datetime.now(dt.timezone.utc)


def eligible(row):
    if not isinstance(row,dict):return False
    if row.get('category') not in ('LOCAL_REMOTE_REVIEW','ACTIVE_AOSP_REVIEW'):return False
    if (row.get('stage')!='AT_SOURCE' or row.get('visibility')!='PUBLIC' or
        row.get('archived') is not False or row.get('fork') is not False):return False
    if not validate_name(row.get('name')):return False
    if not isinstance(row.get('branch'),str) or not row['branch'] or not re.fullmatch('[A-Za-z0-9_./-]{1,200}',row['branch']) or '..' in row['branch']:return False
    if not isinstance(row.get('head_sha'),str) or not re.fullmatch('[0-9a-f]{40}',row['head_sha']):return False
    if not isinstance(row.get('git_remotes'),list):return False
    return all(isinstance(r,dict) and r.get('owner')=='SOURCE' and
               isinstance(r.get('file'),str) and r['file'].startswith('.repo/projects/') and
               r['file'].endswith('/config') and '..' not in Path(r['file']).parts and
               isinstance(r.get('remote'),str) and re.fullmatch('remote\\.[A-Za-z0-9_.-]+\\.url',r['remote'])
               for r in row['git_remotes'])


def row_snapshot(row):
    keys=('name','stage','category','visibility','archived','fork','branch','head_sha',
          'active_manifest_refs','library_manifest_refs','git_remotes')
    return {k:row.get(k) for k in keys}


def candidates(inv):
    a=[row_snapshot(r) for r in inv['repositories'] if eligible(r)]
    # Complete known exact Git remote transitions first, then active framework/device,
    # then active vendor projects. The new manifest checkpoint is a separate step.
    def priority(row):
        name=row['name'];cls=row['category']
        if cls=='LOCAL_REMOTE_REVIEW':return (0,name)
        if name.startswith('android_vendor_'):return (2,name)
        return (1,name)
    return sorted(a,key=priority)


def fingerprint(rows):
    body=json.dumps(rows,sort_keys=True,separators=(',',':'),ensure_ascii=True)
    return hashlib.sha256(body.encode()).hexdigest()[:12]


def plan_path(target):return STATE/('public_core__'+target+'.json')


def _remote(cfg,payload):
    from .cli import ArdaError,ssh_flags
    worker=(PACKAGE_ROOT/'arda_cli'/'org_bulk_worker.py').read_text('utf8')
    anchor='data=json.loads(sys.stdin.read())'
    if worker.count(anchor)!=1:raise ArdaError('Bulk worker contract changed; STOP')
    worker=worker.replace(anchor,'data=json.loads('+repr(json.dumps(payload))+')')
    try:
        p=subprocess.run(['ssh','-T',*ssh_flags(cfg),cfg['ubuntu'],'python3','-'],
                         input=worker,text=True,capture_output=True,timeout=260,errors='replace')
    except (OSError,subprocess.TimeoutExpired):
        raise ArdaError('SSH failed/timeout; if a transfer was being applied, inspect GitHub; never retry automatically') from None
    try:out=json.loads(p.stdout.strip())
    except (ValueError,TypeError):
        raise ArdaError('Ubuntu response unreadable; if transfer was requested, inspect GitHub before retry') from None
    if not isinstance(out,dict):raise ArdaError('Invalid bulk worker response')
    if p.returncode and out.get('status')!='STOP':raise ArdaError('SSH worker returned abnormal status')
    return out


def make_plan(cfg,target):
    from .cli import ArdaError
    inv=inventory_data(cfg,target,enrich_active_sha=True)
    rows=candidates(inv)
    if not rows:raise ArdaError('No eligible public-core repos. No writes.')
    if len(rows)>MAX_BATCH:raise ArdaError('More than 12 public-core repos; split phase before transfer')
    verified=[]
    print(f"[ARDA BATCH] Read-only GitHub preflight: {len(rows)} public repos",flush=True)
    for idx,r in enumerate(rows,1):
        print(f"[ARDA BATCH] Preflight {idx}/{len(rows)}: {r['name']}",flush=True)
        result=_remote(cfg,{'root':cfg['aosp_root'],'target':target,'row':r,'operation':'preflight'})
        if result.get('status')!='READY':
            raise ArdaError('Public-core preflight HOLD for '+r['name']+': '+result.get('error','unknown'))
        verified.append({'repo':r['name'],'source_id':result['source_id'],
                         'source_head':result['head'],'remotes':result['remote_count'],
                         'active_xml_refs':result['active_manifest_ref_count']})
    fp=fingerprint(rows)
    return {'created_utc':_now().isoformat(),'status':'PLAN_READY','target':target,
            'mode':'PUBLIC_CORE_ONLY','fingerprint':fp,'candidates':rows,
            'verified':verified,
            'confirmation':f'TRANSFER {len(rows)} PUBLIC CORE {fp} TO {target}',
            'deferred':['PRIVATE_REVIEW','INDEPENDENT_REVIEW','INFRA_LAST','empty/default-branch-less repos'],
            'manifest_policy':'PRESERVE CURRENT XML; use verified future manifest checkpoint, no repo sync'}


def _plan_valid(plan, inv, target, confirm):
    from .cli import ArdaError
    if plan.get('target')!=target or plan.get('status')!='PLAN_READY':raise ArdaError('Invalid target/plan')
    if confirm!=plan.get('confirmation'):raise ArdaError('Exact --confirm required: '+str(plan.get('confirmation')))
    try:stamp=dt.datetime.fromisoformat(plan['created_utc'])
    except (ValueError,TypeError,KeyError):raise ArdaError('Plan timestamp invalid') from None
    if stamp.tzinfo is None or not 0<=(_now()-stamp).total_seconds()<=MAX_AGE_HOURS*3600:
        raise ArdaError('Batch plan expired; run --plan again')
    fresh=candidates(inv)
    if fresh!=plan['candidates'] or fingerprint(fresh)!=plan['fingerprint']:
        raise ArdaError('Batch inventory drift; run --plan again, no transfers')
    if len(fresh)>MAX_BATCH:raise ArdaError('Batch size exceeded')


def apply(cfg,target,confirm):
    from .cli import ArdaError
    fp=plan_path(target)
    if not fp.is_file():raise ArdaError('Run arda org batch --plan first')
    try:stored=json.loads(fp.read_text('utf8'))
    except (OSError,ValueError):raise ArdaError('Batch plan missing/corrupt') from None
    # First validate snapshot and WHOLE group before issuing one GitHub transfer.
    inv=inventory_data(cfg,target,enrich_active_sha=True)
    _plan_valid(stored,inv,target,confirm)
    ids={x['repo']:x['source_id'] for x in stored['verified']}
    for r in stored['candidates']:
        response=_remote(cfg,{'root':cfg['aosp_root'],'target':target,'row':r,'operation':'preflight'})
        if response.get('status')!='READY' or response.get('source_id')!=ids[r['name']]:
            raise ArdaError('Whole-group preflight failed: '+r['name']+', no transfer started')
    STATE.mkdir(parents=True,exist_ok=True)
    lockfile=STATE/('LOCK__'+target)
    try:
        descriptor=os.open(str(lockfile),os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        os.write(descriptor,b'ARDA bulk transfer in progress; inspect before clearing.\n')
        os.close(descriptor)
    except FileExistsError:
        raise ArdaError('Another bulk operation or unresolved lock exists; inspect state before retry') from None
    path=STATE/('journal_'+_now().strftime('%Y%m%dT%H%M%S%fZ')+'.json')
    journal={'created_utc':_now().isoformat(),'target':target,'fingerprint':stored['fingerprint'],
             'status':'IN_PROGRESS','rows':[{'repo':r['name'],'status':'NOT_STARTED'} for r in stored['candidates']],
             'warning':'GitHub transfers cannot be rolled back atomically. Do not automatically retry an unknown outcome.'}
    atomic_json(path,journal)
    try:
        for index,(r,record) in enumerate(zip(stored['candidates'],journal['rows']),1):
            print(f"[ARDA BATCH] Transfer {index}/{len(stored['candidates'])}: {r['name']}",flush=True)
            # Crash-safe: claim request MAY have been sent before external side effects.
            record['status']='TRANSFER_REQUEST_MAY_HAVE_BEEN_SENT'
            atomic_json(path,journal)
            result=_remote(cfg,{'root':cfg['aosp_root'],'target':target,'row':r,
                                'operation':'transfer','expected_id':ids[r['name']]})
            record['status']=result.get('status','UNKNOWN')
            for key in ('repo_id','branch','head','remotes_updated','active_xml_unchanged'):
                if key in result:record[key]=result[key]
            if record['status']!='COMPLETE':
                record['error']=str(result.get('error','Remote transfer not fully verified'))[:340]
                raise ArdaError(r['name']+': '+record['status']+'; inspect GitHub and Ubuntu before resuming')
            atomic_json(path,journal)
            print('[ARDA BATCH] VERIFIED '+r['name']+'; GitHub ID/SHA/remote checked',flush=True)
        journal['status']='COMPLETE'
    except Exception as exc:
        journal['status']='STOP_PARTIAL_POSSIBLE'
        journal['error']=str(exc)[:400]
    finally:
        journal['completed_utc']=_now().isoformat()
        atomic_json(path,journal)
        lockfile.unlink(missing_ok=True)
    return journal,path


def cmd_org_bulk(cfg,args):
    from .cli import ArdaError
    target=args.target
    if not validate_name(target) or target.casefold()!='arda-aaos':
        raise ArdaError('V1.14 bulk target fixed to arda-aaos for safety')
    if args.plan and args.apply:raise ArdaError('Use one of --plan / --apply')
    if args.apply:
        result,journal=apply(cfg,target,args.confirm)
        status=result['status']
        print('ARDA ORG BATCH — PUBLIC CORE — APPLY')
        for x in result['rows']:
            print('  '+x['repo']+': '+x['status'])
        print('  Status: '+status)
        print('  JOURNAL='+str(journal))
        if status!='COMPLETE':
            print('  STOP: '+str(result.get('error','unknown')))
            print('  DO NOT rerun --apply: examine GitHub and remotes; partial transfers may exist.')
        print('  Active manifest XML unchanged; no repo sync, build, push or device operation.')
    else:
        result=make_plan(cfg,target)
        atomic_json(plan_path(target),result)
        status=result['status']
        print('ARDA ORG BATCH — PUBLIC CORE — READ ONLY')
        print('  Target: '+target)
        print('  Verified public repo count: '+str(len(result['candidates'])))
        for r,v in zip(result['candidates'],result['verified']):
            print('    '+r['name']+' '+r['head_sha'][:12]+' GitHubID='+str(v['source_id'])+
                  ' remotes='+str(v['remotes'])+' activeXML='+str(v['active_xml_refs']))
        print('  Deferred: private, manifest/release, independent ARDA apps, empty repositories')
        print('  CONFIRM='+result['confirmation'])
        print('  SNAPSHOT='+str(plan_path(target)))
        print('  No GitHub or Ubuntu changes made.')
    if args.report:
        cfg['reports'].mkdir(parents=True,exist_ok=True)
        out=cfg['reports']/('ARDA_CLI_V1_14_ORG_BATCH_'+_now().strftime('%Y%m%d_%H%M%S_%f')+'.zip')
        with zipfile.ZipFile(out,'x',compression=zipfile.ZIP_DEFLATED) as z:
            z.writestr('batch.json',json.dumps(result,sort_keys=True,ensure_ascii=False,indent=2)+'\n')
            z.writestr('README.txt','GitHub transfer plan/journal. Manifest XML, AOSP source, builds and device unchanged.\n')
        print('REPORT_ZIP='+str(out))
    return 0 if status in ('PLAN_READY','COMPLETE') else 4
