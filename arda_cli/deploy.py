"""Provenance-bound Cluster staged tests. No implicit build, sync, reboot or push."""
from __future__ import annotations
from datetime import datetime, timezone
import hashlib, json, os, re, shutil, tempfile, zipfile
from pathlib import Path
from . import __version__
from .build import prepare, guard_plan, source_fingerprint
from .cli import ArdaError, run

PACKAGE='android.car.cluster'
PLATFORM='com.github.deadknight.ardaplatform.debug'
PROPS={'persist.arda.cluster.nav_h264_tee':'0','persist.arda.cluster.nav_keeper':'1'}
SETTINGS={'arda_cluster_free_map_mode':'cluster','arda_cluster_map_touch':'off','arda_cluster_map_theme':'vehicle'}
APKPATH=re.compile(r'^out/target/product/[A-Za-z0-9_-]+/(?:system|system_ext|product|vendor)/(?:priv-app|app)/DirectRenderingCluster/DirectRenderingCluster\.apk$')
SHA=re.compile(r'^[0-9a-f]{64}$')

def digest(p):
    h=hashlib.sha256()
    with open(p,'rb') as f:
        for block in iter(lambda:f.read(1048576),b''): h.update(block)
    return h.hexdigest()

def read_receipt(path):
    try:
        with zipfile.ZipFile(path) as z:
            if z.getinfo('SUMMARY.json').file_size>100000: raise ValueError('large report')
            d=json.loads(z.read('SUMMARY.json'))
    except (OSError, ValueError, KeyError, zipfile.BadZipFile) as e:
        raise ArdaError('Invalid build receipt: '+str(e)) from e
    a=d.get('apk',{})
    if not (d.get('version') in ('0.5.0','0.6.0','0.7.0','0.8.0') and d.get('module')=='DirectRenderingCluster'
        and d.get('build')=='PASS' and d.get('device_install') is False
        and d.get('reboot') is False and SHA.fullmatch(d.get('source_sha256',''))
        and re.fullmatch(r'[0-9a-f]{40}',d.get('head_before',''))
        and isinstance(a,dict) and a.get('available') is True
        and SHA.fullmatch(a.get('sha256','')) and APKPATH.fullmatch(a.get('path',''))
        and isinstance(a.get('size'),int) and 4096<a['size']<250_000_000):
        raise ArdaError('Build report lacks V1.4 source/APK provenance')
    return d

def matching_receipt(cfg,state,explicit):
    if explicit:
        paths=[Path(explicit).expanduser()]
    else:
        paths=sorted(cfg['reports'].glob('ARDA_CLI_V1_3_BUILD_*.zip'),
                     key=lambda p:p.stat().st_mtime,reverse=True)
    for path in paths:
        try: d=read_receipt(path)
        except (ArdaError,OSError):
            if explicit: raise
            continue
        if (d['head_before']==state['head'] and
            d['source_sha256']==source_fingerprint(state['files']) and
            d.get('lunch')==cfg['lunch'] and
            d['apk']['path'].startswith('out/target/product/'+cfg['product_dir']+'/')):
            return d,path
    raise ArdaError('No matching ARDA CLI build receipt. Run `arda build DirectRenderingCluster` first.')

def adb(cfg,*args,timeout=35,rc1=False):
    tool=shutil.which('adb') or str(Path.home()/'Library/Android/sdk/platform-tools/adb')
    p=run([tool,'-s',cfg['device'],*args],timeout=timeout)
    out=(p.stdout+'\n'+p.stderr).strip()
    if p.returncode and not(rc1 and p.returncode==1):
        raise ArdaError('ADB '+str(args[:3])+': '+out[-350:])
    return out

def tool_path(name):
    if shutil.which(name): return shutil.which(name)
    sdk=Path.home()/'Library/Android/sdk/build-tools'
    paths=[p for p in sdk.glob('*/'+name) if p.is_file() and os.access(p,os.X_OK)]
    if paths:
        return str(max(paths,key=lambda x:x.stat().st_mtime))
    raise ArdaError('Android SDK build-tools missing '+name)

def identity(path):
    signed=run([tool_path('apksigner'),'verify','--print-certs',str(path)],timeout=80)
    if signed.returncode: raise ArdaError('APK signature check failed')
    hashes=re.findall(r'Signer\s+#\d+\s+certificate\s+SHA-256\s+digest:\s*([0-9a-fA-F:]+)',signed.stdout)
    if len(hashes)!=1: raise ArdaError('APK signing certificate missing or multiple')
    meta=run([tool_path('aapt'),'dump','badging',str(path)],timeout=80)
    if meta.returncode: raise ArdaError('aapt failed; APK identity unverified')
    m=re.search(r"(?m)^package: name='([^']+)' versionCode='(\d+)'",meta.stdout)
    if not m: raise ArdaError('APK package/version metadata missing')
    return {'package':m.group(1),'version':int(m.group(2)), 'signer':hashes[0].replace(':','').lower()}

def active_path(cfg,package):
    out=adb(cfg,'shell','pm','path',package)
    paths=[x[len('package:'):].strip() for x in out.splitlines() if x.startswith('package:') and x.endswith('/base.apk')]
    if len(paths)!=1 or not paths[0].startswith(('/data/app/','/system/','/system_ext/','/vendor/','/product/')) or '..' in paths[0]:
        raise ArdaError('Installed APK path unavailable or ambiguous for '+package)
    return paths[0]

def device_state(cfg):
    if adb(cfg,'get-state',timeout=15)!='device': raise ArdaError('Device not online')
    d={'device':cfg['device'],'props':{},'settings':{}}
    for k,want in PROPS.items():
        v=adb(cfg,'shell','getprop',k,timeout=15)
        d['props'][k]=v
        if v!=want: raise ArdaError('Safety gate: '+k+' expected '+want)
    for k,want in SETTINGS.items():
        v=adb(cfg,'shell','settings','get','global',k,timeout=15)
        d['settings'][k]=v
        if v!=want: raise ArdaError('Safety gate: '+k+' expected '+want)
    for alias,package in [('cluster',PACKAGE),('platform',PLATFORM)]:
        path=active_path(cfg,package)
        m=re.match(r'([0-9a-f]{64})\s',adb(cfg,'shell','sha256sum',path,timeout=45).lower())
        if not m: raise ArdaError('Device SHA unavailable for '+package)
        d[alias+'_path']=path
        d[alias+'_sha']=m.group(1)
    return d

def parse_sessions(raw):
    """Staged status may wrap fields midword; terminal records are not pending."""
    if re.search(r'(?im)^\s*(?:Failure|Error|Exception)\b',raw):
        raise ArdaError('Android staged session query failed')
    flat=re.sub(r'\s*\r?\n\s*','',raw.strip()).strip()
    if not flat: return []
    anchors=list(re.finditer(r'\bsessionId\s*=\s*(\d+)\b',flat))
    if not anchors or flat[:anchors[0].start()].strip():
        raise ArdaError('Ambiguous staged session output')
    rows=[]
    for i,m in enumerate(anchors):
        part=flat[m.start():anchors[i+1].start() if i+1<len(anchors) else len(flat)]
        record={'id':m.group(1)}
        for field,variants in [('applied',('isApplied','isStagedSessionApplied')),
                               ('failed',('isFailed','isStagedSessionFailed')),
                               ('ready',('isReady','isStagedSessionReady'))]:
            matches=[]
            for key in variants:
                match=re.search(r'\b'+key+r'\s*=\s*(true|false)\b',part,re.I)
                if match: matches.append(match.group(1).lower()=='true')
            if not matches or len(set(matches))!=1:
                raise ArdaError('Missing/contradictory staged field '+field+' in session '+record['id'])
            record[field]=matches[0]
        rows.append(record)
    if len(set(x['id'] for x in rows))!=len(rows):
        raise ArdaError('Duplicate staged sessions')
    return rows

def session_guard(cfg):
    sessions=parse_sessions(adb(cfg,'shell','cmd','package','list','staged-sessions',timeout=25,rc1=True))
    pending=[x['id'] for x in sessions if x['ready'] or x['applied']==x['failed']]
    if pending: raise ArdaError('Unresolved staged session(s) '+','.join(pending))
    return len(sessions)

def fetch_apk(cfg,receipt,dest):
    path=receipt['apk']['path']
    if not APKPATH.fullmatch(path) or not path.startswith('out/target/product/'+cfg['product_dir']+'/'):
        raise ArdaError('Invalid signed APK location in receipt')
    p=run(['scp','-B','-i',str(cfg['ssh_key']),'-o','BatchMode=yes',
           '-o','ConnectTimeout=8','-o','StrictHostKeyChecking=yes',
           cfg['ubuntu']+':'+cfg['aosp_root'].rstrip('/')+'/'+path,str(dest)],timeout=180)
    if p.returncode: raise ArdaError('Cannot transfer signed APK: '+p.stderr[-300:])
    if dest.stat().st_size!=receipt['apk']['size'] or digest(dest)!=receipt['apk']['sha256']:
        raise ArdaError('Built APK changed after build receipt; refusing stage')

def report(cfg,kind,summary):
    cfg['reports'].mkdir(parents=True,exist_ok=True)
    stamp=datetime.now().strftime('%Y%m%d_%H%M%S_%f')
    path=cfg['reports']/f'ARDA_CLI_V1_4_{kind.upper()}_{stamp}.zip'
    with zipfile.ZipFile(path,'x',zipfile.ZIP_DEFLATED) as z:
        z.writestr('SUMMARY.json',json.dumps({'version':__version__,'action':kind,
                   'utc':datetime.now(timezone.utc).isoformat(), 'automatic_reboot':False,
                   'repo_sync':False,'git_push':False,**summary},indent=2))
    print('REPORT_ZIP='+str(path))
    return path

def record_path():
    return Path.home()/'.local/share/arda-cli-v1/staged/DirectRenderingCluster.json'

def save_record(data):
    p=record_path(); p.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    fd,tmp=tempfile.mkstemp(dir=p.parent,prefix='.arda-stage-')
    try:
        with os.fdopen(fd,'w') as f: json.dump(data,f,sort_keys=True,indent=2)
        os.chmod(tmp,0o600); os.replace(tmp,p)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)

def stage(cfg,apk,receipt,build_report,device,installed):
    backupdir=cfg['reports']/'ARDA_CLI_BACKUPS'
    backupdir.mkdir(parents=True,exist_ok=True,mode=0o700)
    tag=datetime.now().strftime('%Y%m%d_%H%M%S_%f')
    backup=backupdir/f'DirectRenderingCluster_pretest_{tag}.apk'
    shutil.copy2(installed,backup)
    if digest(backup)!=device['cluster_sha']:
        raise ArdaError('Cluster APK backup integrity failure')
    target='/data/local/tmp/arda-cluster-'+tag+'.apk'
    session=None; committed=False
    try:
        adb(cfg,'push',str(apk),target,timeout=180)
        if not adb(cfg,'shell','sha256sum',target,timeout=40).lower().startswith(digest(apk)+' '):
            raise ArdaError('Uploaded APK SHA mismatch')
        created=adb(cfg,'shell','cmd','package','install-create','--staged','-r','-S',str(apk.stat().st_size),timeout=80)
        m=re.search(r'\[(\d+)\]',created)
        if not m: raise ArdaError('Cannot obtain staged session ID')
        session=m.group(1)
        adb(cfg,'shell','cmd','package','install-write','-S',str(apk.stat().st_size),session,'base.apk',target,timeout=120)
        committed_msg=adb(cfg,'shell','cmd','package','install-commit',session,timeout=120)
        if not re.search(r'\bSuccess\b',committed_msg):
            raise ArdaError('Staged install commit did not return Success')
        committed=True
        data={'package':PACKAGE,'module':'DirectRenderingCluster','device':cfg['device'],
              'session_id':session,'apk_sha256':digest(apk),'previous_cluster_sha256':device['cluster_sha'],
              'platform_sha256':device['platform_sha'],'settings':device['settings'],'props':device['props'],
              'source_sha256':receipt['source_sha256'],'build_report':str(build_report),
              'backup':str(backup),'utc':datetime.now(timezone.utc).isoformat()}
        save_record(data)
        print('RESULT=STAGED_COMMITTED_NO_REBOOT SESSION='+session)
        print('BACKUP_APK='+str(backup))
        report(cfg,'test',{'result':'STAGED_COMMITTED_NO_REBOOT','session':session,
                            'apk_sha256':data['apk_sha256'],'build_report':str(build_report),'backup':str(backup)})
        return 0
    except Exception:
        if session and not committed:
            try: adb(cfg,'shell','cmd','package','install-abandon',session,timeout=25)
            except ArdaError: pass
        # A committed stage cannot safely be undone. If receipt write failed,
        # report that fact; never claim the device was unchanged.
        if committed: print('WARNING: stage committed, but post-commit recording failed. Manual inspection required.')
        raise
    finally:
        try: adb(cfg,'shell','rm','-f',target,timeout=25)
        except ArdaError: pass

def _cmd_test(cfg,args):
    if args.module!='DirectRenderingCluster':
        raise ArdaError('V1.4 enables staged testing only for DirectRenderingCluster')
    if not 1<=args.jobs<=16: raise ArdaError('--jobs must be 1..16')
    if args.plan and (args.build or args.sync):
        raise ArdaError('Plan build/sync separately: arda build MODULE --plan --sync')
    if args.build and args.build_report:
        raise ArdaError('Cannot combine --build and --build-report')
    if args.sync and not args.build:
        raise ArdaError('--sync requires explicit --build')
    if args.build:
        from .build import cmd_build
        print('EXPLICIT_BUILD=YES (live Ubuntu output)',flush=True)
        rc=cmd_build(cfg,args.module,plan=False,sync=args.sync,jobs=args.jobs)
        if rc: return rc
    source=prepare(cfg,args.module)
    decision=guard_plan(source,False)
    if not decision['ready'] or source['files']!=source['remote_files']:
        raise ArdaError('Sources differ or tracked baseline stale; test stopped: '+decision['reason'])
    receipt,receipt_path=matching_receipt(cfg,source,args.build_report)
    with tempfile.TemporaryDirectory(prefix='arda-cli-cluster-test-') as temp:
        apk=Path(temp)/'DirectRenderingCluster.apk'
        fetch_apk(cfg,receipt,apk)
        device=device_state(cfg)
        n=session_guard(cfg)
        installed=Path(temp)/'installed.apk'
        adb(cfg,'pull',device['cluster_path'],str(installed),timeout=180)
        if not installed.is_file() or digest(installed)!=device['cluster_sha']:
            raise ArdaError('Installed APK backup failed or changed during inspection')
        new,old=identity(apk),identity(installed)
        if new['package']!=PACKAGE or old['package']!=PACKAGE:
            raise ArdaError('Unexpected APK package name')
        if new['signer']!=old['signer']:
            raise ArdaError('Installed/new APK signing certificate mismatch')
        if new['version']<old['version']:
            raise ArdaError('Refuse APK version downgrade')
        print('ARDA CLUSTER STAGED TEST PREFLIGHT')
        print('  Device:             '+cfg['device'])
        print('  Source SHA256:      '+receipt['source_sha256'])
        print('  Candidate APK SHA:  '+receipt['apk']['sha256'])
        print('  Existing APK SHA:   '+device['cluster_sha'])
        print('  VersionCode:        '+str(new['version']))
        print('  Previous sessions:  '+str(n)+' terminal; none pending')
        if device['cluster_sha']==receipt['apk']['sha256']:
            print('RESULT=ALREADY_INSTALLED (no stage)')
            report(cfg,'test',{'result':'ALREADY_INSTALLED','apk_sha256':receipt['apk']['sha256']})
            return 0
        if args.plan:
            print('RESULT=READY_TO_STAGE (read-only)')
            report(cfg,'test_plan',{'result':'READY_TO_STAGE','apk_sha256':receipt['apk']['sha256'],
                                    'source_sha256':receipt['source_sha256'],'device':device,
                                    'new_version':new['version']})
            return 0
        # TOCTOU gate: source and target must stay unchanged before installation.
        again=device_state(cfg)
        if again!=device: raise ArdaError('Device state changed during preflight')
        fresh=prepare(cfg,args.module)
        if fresh['head']!=source['head'] or fresh['files']!=source['files'] or fresh['remote_files']!=source['remote_files']:
            raise ArdaError('Source changed during preflight')
        session_guard(cfg)
        return stage(cfg,apk,receipt,receipt_path,device,installed)

def _cmd_verify(cfg,module):
    if module!='DirectRenderingCluster':
        raise ArdaError('V1.4 verify supports only DirectRenderingCluster')
    state=record_path()
    if not state.is_file():
        raise ArdaError('No committed staged Cluster session recorded. Run arda test first.')
    data=json.loads(state.read_text('utf-8'))
    if data.get('module')!=module or data.get('package')!=PACKAGE or data.get('device')!=cfg['device']:
        raise ArdaError('Stage receipt belongs to another device/module')
    if not SHA.fullmatch(data.get('apk_sha256','')) or not SHA.fullmatch(data.get('platform_sha256','')):
        raise ArdaError('Invalid stage receipt SHA')
    device=device_state(cfg)
    if device['cluster_sha']!=data['apk_sha256']:
        raise ArdaError('Staged Cluster APK is not active yet (or SHA mismatch). No modifications made.')
    if device['platform_sha']!=data['platform_sha256'] or device['settings']!=data['settings'] or device['props']!=data['props']:
        raise ArdaError('Platform or safety settings changed since staged test; manual investigation required')
    print('RESULT=PASS_CLUSTER_APK_ACTIVE')
    print('APK_SHA256='+device['cluster_sha'])
    print('PLATFORM_UNCHANGED=YES')
    print('VISUAL_CHECK_REQUIRED=HDMI2 270-degree orientation, Maps, NIGHT_MODE and touch')
    report(cfg,'verify',{'result':'PASS_CLUSTER_APK_ACTIVE','apk_sha256':device['cluster_sha'],
                         'platform_sha256':device['platform_sha'],'session':data['session_id']})
    return 0


def cmd_test(cfg, args):
    try:
        return _cmd_test(cfg, args)
    except (ArdaError, ValueError, OSError) as exc:
        # Never misrepresent a possible post-commit failure as a clean rollback.
        report(cfg, 'test_stop', {'result':'STOP_OR_PARTIAL_REVIEW_SESSION',
                                  'reason':str(exc)[-450:], 'module':args.module})
        raise


def cmd_verify(cfg, module):
    try:
        return _cmd_verify(cfg, module)
    except (ArdaError, ValueError, OSError) as exc:
        report(cfg, 'verify_stop', {'result':'VERIFY_NOT_PASSED',
                                    'reason':str(exc)[-450:], 'module':module})
        raise
