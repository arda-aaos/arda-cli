"""V1.17 guarded final infrastructure transfer after private phase.

Only the two exact infrastructure repositories are in scope. A frozen read-only snapshot, full preflight, fingerprinted
confirmation and crash journal are required before any GitHub transfer.
"""
from __future__ import annotations
import datetime as dt, hashlib, json, os, subprocess, zipfile
from pathlib import Path
from .config import PACKAGE_ROOT
from .org_wave import inventory_data
from .org_migrate import atomic_json

STATE=Path.home()/'.local/share/arda-cli-v1/org-infra'
EXPECTED={'infra':('arda-releases','arda-aaos-manifest')}
MAX_AGE_HOURS=24

def utcnow():return dt.datetime.now(dt.timezone.utc)

def snap(row):
    cols=('name','stage','category','visibility','archived','fork','branch','head_sha',
          'git_remotes','active_manifest_refs','library_manifest_refs')
    return {col:row.get(col) for col in cols}

def pending(inv,phase):
    from .cli import ArdaError
    group=EXPECTED[phase]
    byname={r['name']:r for r in inv['repositories']}
    if len(byname)!=len(inv['repositories']):raise ArdaError('Duplicate GitHub repo inventory; STOP')
    if any(name not in byname for name in group):raise ArdaError('Special group incomplete in GitHub inventory')
    already=[n for n in group if byname[n]['stage']=='TRANSFERRED']
    unexpected=[n for n in group if byname[n]['stage'] not in ('AT_SOURCE','TRANSFERRED')]
    if unexpected:raise ArdaError('Conflicting owner status: '+','.join(unexpected))
    rows=[snap(byname[n]) for n in group if byname[n]['stage']=='AT_SOURCE']
    return rows,already

def digest(rows):
    return hashlib.sha256(json.dumps(rows,sort_keys=True,separators=(',',':')).encode()).hexdigest()[:12]

def state_path(phase):return STATE/(phase+'__arda-aaos.json')

def check_unresolved():
    from .cli import ArdaError
    if STATE.is_dir():
        for fp in STATE.glob('journal_*.json'):
            try:doc=json.loads(fp.read_text('utf8'))
            except (OSError,ValueError):raise ArdaError('Unparseable org-infra journal; manual review required') from None
            if doc.get('status') not in ('COMPLETE',):
                raise ArdaError('Previous org-infra transfer unresolved: '+str(fp)+ '; inspect before any new transfer')

def worker(cfg,data):
    from .cli import ArdaError,ssh_flags
    source=(PACKAGE_ROOT/'arda_cli'/'org_infra_worker.py').read_text('utf8')
    marker='data=json.loads(sys.stdin.read())'
    if source.count(marker)!=1:raise ArdaError('org-infra worker contract changed; STOP')
    payload=json.dumps(data,sort_keys=True,separators=(',',':'))
    source=source.replace(marker,'data=json.loads('+repr(payload)+')')
    try:
        response=subprocess.run(['ssh','-T',*ssh_flags(cfg),cfg['ubuntu'],'python3','-'],
              input=source,encoding='utf8',capture_output=True,errors='replace',timeout=300)
    except (OSError,subprocess.TimeoutExpired):
        raise ArdaError('SSH failed/timeout; inspect GitHub before retrying any transfer') from None
    try:result=json.loads(response.stdout.strip())
    except (ValueError,TypeError):
        raise ArdaError('Worker response unreadable; inspect GitHub before retrying') from None
    if not isinstance(result,dict):raise ArdaError('org-infra worker response invalid')
    if response.returncode and result.get('status')!='STOP':
        raise ArdaError('SSH worker exited abnormally; inspect GitHub before retrying')
    return result

def payload(cfg,phase,row,operation,**kwargs):
    return {'root':cfg['aosp_root'],'target':'arda-aaos',
            'phase':phase,'row':row,'operation':operation,**kwargs}

def mkplan(cfg,phase):
    from .cli import ArdaError
    inventory=inventory_data(cfg,'arda-aaos')
    rows,already=pending(inventory,phase)
    if (inventory.get('total_distinct')!=22 or inventory.get('target_present')!=20 or
        inventory.get('source_remaining')!=2 or len(rows)!=2 or already or
        {r['name'] for r in rows}!={'arda-releases','arda-aaos-manifest'}):
        raise ArdaError('Infrastructure migration requires exactly 20/22 transferred, two source infra repos')
    if any(r.get('stage')!='TRANSFERRED' for r in inventory['repositories'] if r['name'] not in EXPECTED['infra']):
        raise ArdaError('Non-infrastructure repository is still at source')
    if any(x.get('owner')=='SOURCE' for r in inventory['repositories'] for x in r.get('git_remotes',[]) if r['stage']=='TRANSFERRED'):
        raise ArdaError('Transferred repository still has source-owned Ubuntu remote')

    verified=[]
    print('[ARDA INFRA] Read-only preflight '+phase+': '+str(len(rows))+' repositories',flush=True)
    for i,row in enumerate(rows,1):
        print(f"[ARDA INFRA] Preflight {i}/{len(rows)}: {row['name']}",flush=True)
        r=worker(cfg,payload(cfg,phase,row,'preflight'))
        if r.get('status')!='READY':raise ArdaError('Preflight HOLD for '+row['name']+': '+str(r.get('error','unknown')))
        verified.append({'repo':row['name'],'source_id':r['source_id'],
                         'branch':r['branch'],'head':r['head'],'visibility':r['visibility'],
                         'remote_count':r['remote_count'],'active_xml_refs':r['active_xml_count'],
                         'private_access':r['private_access'],'manifest':r['manifest']})
    if (verified[0]['private_access']!=verified[1]['private_access'] or
        verified[0]['manifest']!=verified[1]['manifest']):
        raise ArdaError('Access or AOSP manifest changed while generating infra plan')
    fp=digest(rows)
    return {'created_utc':utcnow().isoformat(),'status':'PLAN_READY',
      'target':'arda-aaos','phase':phase,'fingerprint':fp,
      'candidates':rows,'verified':verified,'already_transferred':already,
      'confirmation':f'TRANSFER {len(rows)} INFRA {fp} TO arda-aaos',
      'manifest_policy':'No XML edits; existing historical SHA/checkpoints unchanged',
      'persist_policy':'HOLD; owner-aware persist not enabled',
      'acl_disclaimer':'Current private access snapshot only; no before-transfer grant baseline exists',
      'infra_sequence':'arda-releases first, arda-aaos-manifest last; no manifest edits',
      'repository_content_policy':'No GitHub commit/push; repo contents stay at verified SHA; old owner URLs remain for later owner-aware checkpoint' }

def validate_plan(cfg,phase,confirmation):
    from .cli import ArdaError
    fp=state_path(phase)
    if not fp.is_file():raise ArdaError('Run arda org infra --plan first')
    try:plan=json.loads(fp.read_text('utf8'))
    except (OSError,ValueError):raise ArdaError('Infra plan missing/corrupt') from None
    if plan.get('phase')!=phase or plan.get('target')!='arda-aaos' or plan.get('status')!='PLAN_READY':
        raise ArdaError('Invalid infra plan; STOP')
    if confirmation!=plan.get('confirmation'):
        raise ArdaError('Exact --confirm required: '+str(plan.get('confirmation')))
    try:stamp=dt.datetime.fromisoformat(plan['created_utc'])
    except (KeyError,ValueError,TypeError):raise ArdaError('Tail plan timestamp invalid') from None
    if stamp.tzinfo is None or not 0<=(utcnow()-stamp).total_seconds()<=MAX_AGE_HOURS*3600:
        raise ArdaError('Tail plan expired; request new --plan')
    inv=inventory_data(cfg,'arda-aaos')
    rows,already=pending(inv,phase)
    if rows!=plan['candidates'] or already!=plan['already_transferred'] or digest(rows)!=plan['fingerprint']:
        raise ArdaError('Inventory drift since plan; STOP before transfer')
    verified=plan.get('verified')
    if not isinstance(verified,list) or len(verified)!=len(rows):raise ArdaError('Frozen verification count invalid')
    for row, v in zip(rows,verified):
        if v['repo']!=row['name'] or not isinstance(v.get('source_id'),int):
            raise ArdaError('Frozen repository identity invalid')
        r=worker(cfg,payload(cfg,phase,row,'preflight'))
        if r.get('status')!='READY' or any((r.get(a)!=v.get(b)) for a,b in (
            ('source_id','source_id'),('head','head'),('branch','branch'),
            ('visibility','visibility'),('remote_count','remote_count'),
            ('active_xml_count','active_xml_refs'),('private_access','private_access'),
            ('manifest','manifest'))):
            raise ArdaError('Full-group preflight drift: '+row['name']+', no transfer started')
    return plan

def execute(cfg,phase,confirmation):
    from .cli import ArdaError
    check_unresolved()
    plan=validate_plan(cfg,phase,confirmation)
    STATE.mkdir(parents=True,exist_ok=True)
    lock=STATE/'LOCK__arda-aaos'
    try:
        fd=os.open(str(lock),os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        os.write(fd,b'org-infra migration in progress. Inspect journal before clearing.\n')
        os.close(fd)
    except FileExistsError:raise ArdaError('Existing org-infra lock; inspect before retry') from None
    journal_path=STATE/('journal_'+utcnow().strftime('%Y%m%dT%H%M%S%fZ')+'.json')
    journal={'created_utc':utcnow().isoformat(),'phase':phase,'target':'arda-aaos',
        'fingerprint':plan['fingerprint'],'status':'IN_PROGRESS',
        'rows':[{'repo':x['name'],'status':'NOT_STARTED'} for x in plan['candidates']],
        'warning':'Transfers are not atomic. Never retry an unknown outcome without manual reconciliation.'}
    try:
        atomic_json(journal_path,journal)
        for i,(row,entry,verified) in enumerate(zip(plan['candidates'],journal['rows'],plan['verified']),1):
            print(f"[ARDA INFRA] Transfer {i}/{len(plan['candidates'])}: {row['name']}",flush=True)
            entry['status']='TRANSFER_REQUEST_MAY_HAVE_BEEN_SENT'
            atomic_json(journal_path,journal)
            result=worker(cfg,payload(cfg,phase,row,'transfer',
                        expected_id=verified['source_id'],expected_head=verified['head'],
                        expected_access=verified['private_access'],
                        expected_manifest=verified['manifest']))
            entry['status']=result.get('status','UNKNOWN')
            for k in ('repo_id','head','branch','visibility','remotes_updated','active_xml_unchanged'):
                if k in result:entry[k]=result[k]
            if entry['status']!='COMPLETE':
                entry['error']=str(result.get('error','GitHub or remote verification incomplete'))[:340]
                raise ArdaError(row['name']+': '+entry['status']+' — inspect GitHub and Ubuntu')
            atomic_json(journal_path,journal)
            print('[ARDA INFRA] VERIFIED '+row['name']+'; ID/SHA/visibility/exact remote',flush=True)
        journal['status']='COMPLETE'
    except Exception as exc:
        journal['status']='STOP_PARTIAL_POSSIBLE'
        journal['error']=str(exc)[:400]
    finally:
        journal['completed_utc']=utcnow().isoformat()
        atomic_json(journal_path,journal)
        # Fail-closed: leave a lock on any failure so a mistaken rerun cannot transfer
        # the next repository without an explicit manual inspection.
        if journal['status']=='COMPLETE':lock.unlink(missing_ok=True)
    return journal,journal_path

def cmd_org_infra(cfg,args):
    from .cli import ArdaError
    if args.target!='arda-aaos':raise ArdaError('org infra target must be arda-aaos')
    if args.plan and args.apply:raise ArdaError('Choose --plan or --apply')
    phase='infra'
    if args.apply:
        result,journal=execute(cfg,phase,args.confirm)
        print('ARDA ORG INFRA — '+phase.upper()+' — APPLY')
        for x in result['rows']:print('  '+x['repo']+': '+x['status'])
        print('  Status: '+result['status'])
        print('  JOURNAL='+str(journal))
        print('  No manifest edit, repo sync, build, source push or reboot.')
        status=result['status']
    else:
        result=mkplan(cfg,phase)
        STATE.mkdir(parents=True,exist_ok=True)
        atomic_json(state_path(phase),result)
        print('ARDA ORG INFRA — '+phase.upper()+' — READ ONLY')
        for r in result['verified']:
            print('  '+r['repo']+' '+str(r['head'] or '(no branches)')[:12]+
                  ' GitHubID='+str(r['source_id'])+' VIS='+r['visibility']+
                  ' remotes='+str(r['remote_count'])+' activeXML='+str(r['active_xml_refs']))
        print('  CONFIRM='+result['confirmation'])
        print('  SNAPSHOT='+str(state_path(phase)))
        print('  Private access: CURRENT observations (no historical baseline); no grants changed.')
        print('  Frozen AOSP XML SHA256: '+result['verified'][0]['manifest']['digest'][:16])
        print('  No manifest edits or transfers made; releases first, manifest last on apply.')
        status=result['status']
    if args.report:
        cfg['reports'].mkdir(parents=True,exist_ok=True)
        report=cfg['reports']/('ARDA_CLI_V1_17_ORG_INFRA_'+utcnow().strftime('%Y%m%d_%H%M%S_%f')+'.zip')
        with zipfile.ZipFile(report,'x',compression=zipfile.ZIP_DEFLATED) as z:
            z.writestr('org-infra.json',json.dumps(result,indent=2,sort_keys=True,ensure_ascii=False)+'\n')
            z.writestr('README.txt','Private ACL counts (not usernames), hashes and transfer metadata only. No tokens or private source.\n')
        print('REPORT_ZIP='+str(report))
    return 0 if status in ('PLAN_READY','COMPLETE') else 4
