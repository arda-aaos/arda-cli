"""Local configuration and validated, explicitly profiled modules."""
from __future__ import annotations
import os
from pathlib import Path
try:
    import tomllib
except ImportError as exc:
    raise SystemExit('ARDA CLI requires Python 3.11+ (tomllib)') from exc

PACKAGE_ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = Path(os.environ.get('ARDA_CONFIG', '~/.config/arda/config.toml')).expanduser()
DEFAULT_CONFIG = '''# ARDA CLI v1.11 - macOS local controller
[connection]
ubuntu = "builder@build-host"
ssh_key = "~/.ssh/id_ed25519"
aosp_root = "/opt/arda/aosp"
device = "192.0.2.20:5555"
lunch = "aosp_rpi4_car-bp4a-userdebug"
product_dir = "rpi4"

[workspace]
sources = "~/arda/sources"
platform = "~/arda/ArdaPlatform"
reports = "~/Downloads"
'''

# AOSP build-target names are primary keys. Entries marked 'candidate' are
# path hypotheses until module-info.json confirms their actual build target.
PROFILES = {
    'DirectRenderingCluster': {
        'kind': 'aosp-apk', 'source': 'packages/apps/Car/Cluster',
        'module': 'DirectRenderingCluster', 'confidence': 'confirmed_v42',
        'pull': True, 'deploy': 'staged_receipt_v1_4',
    },
    'CarSystemUI': {
        'kind': 'aosp-apk', 'source': 'packages/apps/Car/SystemUI',
        'module': 'CarSystemUI', 'confidence': 'candidate',
        'pull': True, 'deploy': 'not_implemented',
    },
    'CarLauncher': {
        'kind': 'aosp-apk', 'source': 'packages/apps/Car/Launcher',
        'module': 'CarLauncher', 'confidence': 'candidate',
        'pull': True, 'deploy': 'not_implemented',
    },
    'ArdaPlatform': {
        'kind': 'mac-gradle', 'source': '', 'module': ':app:assembleDebug',
        'confidence': 'confirmed_v42', 'pull': False,
        'deploy': 'not_implemented',
    },
    'arda-connectivityd': {
        'kind': 'rust-service', 'source': 'vendor/arda/ardaplatform',
        'module': 'arda-connectivityd', 'confidence': 'candidate',
        'pull': False,  # shared repo contains signing assets: never bulk-copy
        'deploy': 'not_implemented',
    },
}


def expand(path: str) -> Path:
    return Path(os.path.expandvars(path)).expanduser()


def read_config() -> dict:
    if CONFIG_PATH.is_file():
        with CONFIG_PATH.open('rb') as f:
            data = tomllib.load(f)
    else:
        data = tomllib.loads(DEFAULT_CONFIG)
    c = data.get('connection', {})
    w = data.get('workspace', {})
    cfg = {
        'ubuntu': c.get('ubuntu', 'builder@build-host'),
        'ssh_key': expand(c.get('ssh_key', '~/.ssh/id_ed25519')),
        'aosp_root': c.get('aosp_root', '/opt/arda/aosp'),
        'lunch': c.get('lunch', 'aosp_rpi4_car-bp4a-userdebug'),
        'product_dir': c.get('product_dir', 'rpi4'),
        'device': c.get('device', '192.0.2.20:5555'),
        'sources': expand(w.get('sources', '~/arda/sources')),
        'platform': expand(w.get('platform', '~/arda/ArdaPlatform')),
        'reports': expand(w.get('reports', '~/Downloads')),
    }
    if not cfg['aosp_root'].startswith('/') or '..' in Path(cfg['aosp_root']).parts:
        raise ValueError('aosp_root must be an absolute normalized path')
    if any(x.isspace() for x in cfg['ubuntu']) or cfg['ubuntu'].startswith('-') or ':' in cfg['ubuntu']:
        raise ValueError('Invalid Ubuntu SSH host')
    import re
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', cfg['lunch']):
        raise ValueError('Invalid AOSP lunch target')
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', cfg['product_dir']):
        raise ValueError('Invalid AOSP output product directory')
    return cfg


def profile(name: str) -> dict:
    p = PROFILES.get(name)
    if p is None:
        raise ValueError(f'Unknown managed module: {name}. Use `arda list`.')
    return p


def local_root(cfg: dict, name: str) -> Path:
    p = profile(name)
    if p['kind'] == 'mac-gradle':
        return cfg['platform']
    return cfg['sources'].joinpath(*Path(p['source']).parts)
