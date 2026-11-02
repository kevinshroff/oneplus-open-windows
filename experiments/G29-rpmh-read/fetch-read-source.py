"""Fetch the three exact-hash U-Boot reference files; do not execute them."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import urllib.request

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--catalog', required=True, type=Path)
p.add_argument('--output', required=True, type=Path)
a = p.parse_args()
catalog = json.loads(a.catalog.read_text())
assert catalog['repository'] == 'u-boot/u-boot'
assert catalog['commit'] == 'ece349ade2973e220f524ce59e59711cc919263f'
assert len(catalog['files']) == 3
a.output.mkdir(parents=True, exist_ok=False)
rows = []
for row in catalog['files']:
    path = PurePosixPath(row['path'])
    assert not path.is_absolute() and '..' not in path.parts
    url = 'https://raw.githubusercontent.com/u-boot/u-boot/' + catalog['commit'] + '/' + str(path)
    assert row['url'] == url and 0 < row['bytes'] < 2000000
    with urllib.request.urlopen(url, timeout=30) as response:
        data = response.read(row['bytes'] + 1)
    assert len(data) == row['bytes'] and hashlib.sha256(data).hexdigest() == row['sha256']
    out = a.output / path
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(data)
    rows.append({k: row[k] for k in ['path', 'url', 'bytes', 'sha256']})
(a.output / 'fetch-receipt.json').write_text(json.dumps({'files': rows, 'all_hashes_match': True, 'code_executed': False}, indent=2) + '\n')
print(json.dumps({'files': len(rows), 'all_hashes_match': True, 'code_executed': False}))
