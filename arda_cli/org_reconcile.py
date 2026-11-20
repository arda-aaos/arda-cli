"""V1.15.2 organizational reconciliation after public-core transfer.

Read-only; does not change AOSP manifests, remote URLs, GitHub ownership, or
persist publication paths. Fail closed if metadata is inaccessible.
"""
from __future__ import annotations
import datetime as dt, json, re, subprocess, zipfile
from pathlib import Path
from .config import PACKAGE_ROOT
from .org_wave import inventory_data

def pending_group(row):
    name=row['name'];cls=row['category']
    if name in ('arda-aaos-manifest','arda-releases'):return 'INFRA_LAST'
    if row['visibility']=='PRIVATE':return 'PRIVATE_REVIEW'
    if name=='android_external_libudev-zero':return 'EMPTY_FORK_REVIEW'
    if name in ('ArdaPlatform','arda-aaos-vendor'):return 'INDEPENDENT_OWNER_POLICY_FIRST'
    return 'HOLD_'+cls

def owner_policy_sites():
    """No content values or secrets; list only hardcoded owner references in shipped CLI."""
    paths=[]
    for fp in sorted((PACKAGE_ROOT/'arda_cli').glob('*.py')):
        if fp.name.startswith('org_'):continue  # migration-specific old-owner references are intentional
        body=fp.read_text('utf8')
        matches=[i for i,line in enumerate(body.splitlines(),1)
                 if re.search(r'(?i)deadknight/',line)]
        if matches:paths.append({'file':fp.name,'lines':matches[:80],'count':len(matches)})
    return paths

def run_worker(cfg,rows,target):
    from .cli import ArdaError,ssh_flags
    worker=(PACKAGE_ROOT/'arda_cli'/'org_reconcile_worker.py').read_text('utf8')
    marker='payload=json.loads(sys.stdin.read())'
    if worker.count(marker)!=1:raise ArdaError('Reconcile worker source contract changed; STOP')
    # Send only metadata, never repository contents or GitHub tokens.
    minimal=[{k:r.get(k) for k in ('name','stage','category','branch','head_sha','visibility',
                'archived','git_remotes','active_manifest_refs')} for r in rows]
    data={'root':cfg['aosp_root'],'target':target,'repositories':minimal}
    worker=worker.replace(marker,'payload=json.loads('+repr(json.dumps(data,separators=(',',':')))+')')
    try:
        p=subprocess.run(['ssh','-T',*ssh_flags(cfg),cfg['ubuntu'],'python3','-'],
                         input=worker,encoding='utf8',capture_output=True,timeout=420,errors='replace')
    except (OSError,subprocess.TimeoutExpired):
        raise ArdaError('Reconcile SSH/metadata timeout; no changes') from None
    try:out=json.loads(p.stdout.strip())
    except (TypeError,ValueError):raise ArdaError('Reconcile metadata invalid; no changes') from None
    if p.returncode or out.get('status')!='RECONCILE_READ_ONLY_PASS':
        raise ArdaError('Reconcile verification stopped; no changes: '+str(out.get('error','unknown')))
    return out

def build_result(inv, verified, policies):
    """Summarize *verified* worker rows; reject incomplete or mixed contracts.

    Repo identity is canonical `name`. The worker retains the legacy `repo`
    alias for existing consumers, but both must agree when present.
    """
    from .cli import ArdaError
    rows = verified.get('repositories')
    if not isinstance(rows, list) or not rows:
        raise ArdaError('Reconcile verified repository set missing; no changes')
    required = ('name', 'repo', 'stage', 'visibility', 'category', 'default_branch',
                'head_sha', 'stale_source_remotes', 'branch_state')
    seen = set()
    for r in rows:
        if not isinstance(r, dict) or any(k not in r for k in required):
            raise ArdaError('Reconcile verified repository schema mismatch; no changes')
        if not isinstance(r['name'], str) or not r['name'] or r['name'] != r['repo']:
            raise ArdaError('Reconcile repository name mismatch; no changes')
        if r['name'].casefold() in seen:
            raise ArdaError('Reconcile duplicate repository; no changes')
        seen.add(r['name'].casefold())
        if r['stage'] not in ('AT_SOURCE', 'TRANSFERRED'):
            raise ArdaError('Reconcile unexpected repository stage; no changes')
        if not isinstance(r['stale_source_remotes'], int) or r['stale_source_remotes'] < 0:
            raise ArdaError('Reconcile remote count invalid; no changes')
        if r['branch_state'] not in ('NO_BRANCHES_VERIFIED', 'BRANCH_SHA_VERIFIED'):
            raise ArdaError('Reconcile branch verification missing; no changes')
        if r['branch_state'] == 'NO_BRANCHES_VERIFIED' and (r['default_branch'] is not None or r['head_sha'] is not None):
            raise ArdaError('Reconcile branchless metadata inconsistent; no changes')
        if r['branch_state'] == 'BRANCH_SHA_VERIFIED' and (not r['default_branch'] or not re.fullmatch(r'[0-9a-f]{40}', r['head_sha'] or '')):
            raise ArdaError('Reconcile SHA verification missing; no changes')
    transferred = sum(r['stage'] == 'TRANSFERRED' for r in rows)
    remaining = sum(r['stage'] == 'AT_SOURCE' for r in rows)
    if (verified.get('github_verified_count') != len(rows) or
            verified.get('transferred_verified') != transferred or
            verified.get('remaining_verified') != remaining):
        raise ArdaError('Reconcile verified repository counts inconsistent; no changes')
    manifest = verified.get('manifest_owner_urls')
    if not isinstance(manifest, list) or any(
            not isinstance(m, dict) or
            not isinstance(m.get('old_owner_url_attributes'), int) or
            not isinstance(m.get('new_owner_url_attributes'), int)
            for m in manifest):
        raise ArdaError('Reconcile manifest summary invalid; no changes')
    pending = [{'name': r['name'], 'visibility': r['visibility'],
                'review': pending_group(r),
                'default_branch': r['default_branch'], 'head_sha': r['head_sha'],
                'branch_state': r['branch_state'],
                'stale_source_remotes': r['stale_source_remotes']}
               for r in rows if r['stage'] == 'AT_SOURCE']
    stale = [{'name': r['name'], 'stale': r['stale_source_remotes']}
             for r in rows if r['stage'] == 'TRANSFERRED' and r['stale_source_remotes']]
    return {'status': 'RECONCILE_READ_ONLY_PASS', 'target': inv['target'],
            'verified_repos': len(rows), 'transferred': transferred,
            'remaining': remaining, 'no_branch_repos_verified': sum(
                r['branch_state'] == 'NO_BRANCHES_VERIFIED' for r in rows),
            'pending': pending, 'stale_transferred_remotes': stale,
            'manifest_owner_urls': manifest,
            'cli_owner_policy_sites': policies,
            'persist_policy': 'HOLD_OWNER_AWARE_UPDATE_REQUIRED',
            'next_phases': {'public_independent': 'ArdaPlatform + arda-aaos-vendor (separate owner-aware persist)',
                            'empty_fork': 'libudev-zero: verify empty/default-branch and patch strategy',
                            'private': '3 private repos; explicit visibility and org access review',
                            'infrastructure': 'manifest + release repositories last; preserve historical pins'},
            'no_writes': True}

def cmd_org_reconcile(cfg,args):
    from .cli import ArdaError,format_table
    target=args.target
    if target!='arda-aaos':raise ArdaError('V1.15 reconcile target must be arda-aaos')
    inv=inventory_data(cfg,target)
    verified=run_worker(cfg,inv['repositories'],target)
    result=build_result(inv,verified,owner_policy_sites())
    if args.json:print(json.dumps(result,sort_keys=True,indent=2,ensure_ascii=False))
    else:
        print('ARDA ORG RECONCILIATION — READ ONLY')
        print('  Target:         '+target)
        print('  Verified GitHub:'+str(result['verified_repos']))
        print('  Transferred:    '+str(result['transferred']))
        print('  Remaining:      '+str(result['remaining']))
        print('  No-branch repos verified: '+str(result['no_branch_repos_verified']))
        rows=[(x['name'],x['visibility'],x['review'],x['default_branch'] or '(none)',
               x['head_sha'][:12] if x['head_sha'] else '(none)') for x in result['pending']]
        format_table(('PENDING REPO','VIS','GATE','BRANCH','HEAD'),rows)
        print('  Stale remote URLs after transfer: '+str(sum(x['stale'] for x in result['stale_transferred_remotes'])))
        print('  Manifest files with old owner URLs: '+str(sum(x['old_owner_url_attributes']>0 for x in result['manifest_owner_urls'])))
        print('  CLI persist policy: HOLD until org-aware destination SHA and remote safeguards verified')
        print('  Policy references: '+', '.join(x['file'] for x in result['cli_owner_policy_sites']))
        print('  No GitHub transfer, source/manifest rewrite, commit/push, build, repo sync or reboot.')
        print('RESULT=RECONCILE_READ_ONLY_PASS')
    if args.report:
        cfg['reports'].mkdir(parents=True,exist_ok=True)
        out=cfg['reports']/('ARDA_CLI_V1_15_2_ORG_RECONCILE_'+dt.datetime.now(dt.timezone.utc).strftime('%Y%m%d_%H%M%S')+'.zip')
        with zipfile.ZipFile(out,'x',compression=zipfile.ZIP_DEFLATED) as z:
            z.writestr('reconcile.json',json.dumps(result,sort_keys=True,indent=2,ensure_ascii=False)+'\n')
            z.writestr('README.txt','Read-only metadata audit. No GitHub or Ubuntu writes. No secret content included.\n')
        print('REPORT_ZIP='+str(out))
    return 0
