"""V1.6 release verification. Read-only; never commits/pushes/builds/reboots."""
from __future__ import annotations
import json
from .config import PROFILES
from .release_refs import RECORDS, RELEASE_MANIFEST_SHA
from .persist_plan import persist_one


def audit_one(cfg, name):
    from .cli import remote
    plan = persist_one(cfg,name)
    audit={'module':name,'strategy':plan['strategy'],'plan_readiness':plan['readiness'],
           'github_commit_verified':False,'patch_clean_replay_verified':False,
           'secret_history_audited':False,'status':'NOT_VERIFIED','reason':'unknown'}
    if plan['readiness']!='NO_NEW_SOURCE_CHANGES_DETECTED':
        audit.update(status='HOLD',reason='source_changes_or_unresolved_flags')
        return audit
    if plan['strategy']=='PATCH' and plan['git_path']=='packages/apps/Car/Cluster':
        result=remote(cfg,'persist_audit',source=plan['git_path'],record=RECORDS[plan['git_path']])
        audit.update(status='PASS_CHECKPOINT_REPLAY' if result.get('verified') else 'HOLD',
                     reason=result.get('reason','unknown'),
                     github_commit_verified=result.get('manifest_sha_verified',False),
                     patch_clean_replay_verified=result.get('clean_replay_verified',False),
                     metadata=result)
    elif name=='CarLauncher':
        result=remote(cfg,'launcher_audit')
        audit.update(status='PASS_FORK_PIN' if result.get('verified') else 'HOLD',
                     reason=result.get('reason','unknown'),
                     github_commit_verified=result.get('verified',False),metadata=result)
    elif name in ('ArdaPlatform','arda-connectivityd'):
        project='arda-aaos/ArdaPlatform' if name=='ArdaPlatform' else 'arda-aaos/android_vendor_arda_ardaplatform'
        rec=RECORDS['ArdaPlatform' if name=='ArdaPlatform' else 'vendor/arda/ardaplatform']
        if plan['head']!=rec['release_head']:
            audit.update(status='HOLD',reason='local_sha_differs_from_v49_7')
        else:
            result=remote(cfg,'verify_github_pin',repository=project,sha=rec['release_head'])
            audit.update(status='PASS_GITHUB_COMMIT' if result.get('verified') else 'HOLD',
                         reason=result.get('reason','unknown'),
                         github_commit_verified=result.get('verified',False), metadata=result)
    else:
        audit.update(status='NOT_ASSESSED',reason='no_verified_release_pin_for_this_profile')
    return audit


def cmd_audit(cfg,args):
    from .cli import ArdaError, format_table, report
    if args.all and args.module: raise ArdaError('Use either MODULE or --all')
    if not args.all and not args.module: raise ArdaError('Specify a module or --all')
    rows=[audit_one(cfg,n) for n in sorted(PROFILES) if args.all] if args.all else [audit_one(cfg,args.module)]
    if args.json:
        print(json.dumps(rows,ensure_ascii=False,indent=2))
    elif len(rows)==1:
        r=rows[0]
        print('ARDA PERSIST AUDIT (READ-ONLY)')
        for k in ('module','strategy','plan_readiness','status','reason','github_commit_verified','patch_clean_replay_verified','secret_history_audited'):
            print(f'  {k:30}: {r[k]}')
        print('  No commit/push, source sync, build, reboot or APK install.')
    else:
        format_table(('MODULE','STRATEGY','GITHUB','REPLAY','STATUS'),
                     [(r['module'],r['strategy'],str(r['github_commit_verified']),
                       str(r['patch_clean_replay_verified']),r['status']) for r in rows])
    print('RESULT=AUDIT_READ_ONLY')
    if args.report: report(cfg,'persist_audit',{'rows':rows})
    return 0 if all(r['status'].startswith('PASS_') for r in rows) else 3
