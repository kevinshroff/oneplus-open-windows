"""Verify/extract the exact G24 donor artifacts from the retained official MSI.

No installation or execution. Existing outputs must match and are never replaced.
Private binary destinations are excluded from Git. Requires 7z on PATH.
"""
from pathlib import Path
import argparse, hashlib, json, subprocess

W = Path(__file__).resolve().parent
MSI_SHA = '0917d206fb35278b4df4be980240318475300f3a130a86edac836519059a453d'


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--msi', required=True, type=Path)
    p.add_argument('--extract', action='store_true')
    a = p.parse_args()
    with a.msi.open('rb') as f:
        h = hashlib.sha256()
        while block := f.read(1024 * 1024):
            h.update(block)
    assert h.hexdigest() == MSI_SHA
    for receipt, folder in [('SCM-extraction.json','scm-candidate'),
                             ('PEP-extraction.json','pep-candidate')]:
        r = json.loads((W / receipt).read_text())
        assert r['source_msi_sha256'] == MSI_SHA
        target = W / 'private' / folder
        target.mkdir(parents=True, exist_ok=True)
        for entry in r['files']:
            dst = target / entry['file']
            if not dst.exists():
                assert a.extract, 'Missing retained artifact; use explicit --extract'
                result = subprocess.run(['7z','e','-so',str(a.msi),entry['msi_file_key']],
                                        stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True)
                data = result.stdout
                assert len(data) == entry['bytes']
                assert hashlib.sha256(data).hexdigest() == entry['sha256']
                with dst.open('xb') as f:
                    f.write(data)
            data = dst.read_bytes()
            assert len(data) == entry['bytes']
            assert hashlib.sha256(data).hexdigest() == entry['sha256']
            print(entry['file'], entry['bytes'], entry['sha256'])


if __name__ == '__main__':
    main()
