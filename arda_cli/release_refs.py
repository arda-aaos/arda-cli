"""Historical *observed* release reference points, not live GitHub truth.

V49.7 source SHA values came from ARDA_V49_7_PERSIST_20261116_173152.zip.
Do not treat these refs as current without comparing live local HEAD/manifest.
"""
RELEASE = '2026-11-16-v49.7'
RELEASE_MANIFEST_SHA = 'a85ead3d1d0973e73d7ff34a0cd2d1d67f1ceb0f'
RECORDS = {
    'packages/apps/Car/Cluster': {
        'strategy': 'PATCH', 'baseline': '7244742c0268e1a1f6e88f5b2e1df0c0ec2c825a',
        'release_head': '381ec76af237a746c48c9b1efa62d58f7b9b246e',
        'release': RELEASE,
    },
    'external/libudev-zero': {
        'strategy': 'PATCH', 'baseline': '6f093b428ecae5138654b61d7f29871cef8739dc',
        'release_head': 'b80b0efddfed7fcef2659955f0ae8f7bea124a0e',
        'release': RELEASE,
    },
    'vendor/arda/ardaplatform': {
        'strategy': 'DIRECT', 'baseline': None,
        'release_head': 'f1339bf1294c63a6378e6d344b5177e65c0a3176',
        'release': RELEASE,
    },
    'ArdaPlatform': {
        'strategy': 'DIRECT', 'baseline': None,
        'release_head': '3b29dabd92b09d444346f94703c1a61a2711b96d',
        'release': RELEASE,
    },
}
