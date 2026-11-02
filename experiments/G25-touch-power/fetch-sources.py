"""Fetch or verify only the exact public sources pinned by the G25 receipts."""
from pathlib import Path
import argparse,hashlib,json,urllib.request
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--receipts',required=True,type=Path)
p.add_argument('--output-dir',required=True,type=Path)
a=p.parse_args();a.output_dir.mkdir(parents=True,exist_ok=True)
seen=set()
for name in ['source-receipt.json','kernel-source-receipt.json']:
    j=json.loads((a.receipts/name).read_text())
    for row in j['files']:
        assert '/'+j['commit']+'/'in row['url']
        assert row['url'].startswith('https://raw.githubusercontent.com/'+j['repository']+'/')
        base=Path(row['file']).name;assert base not in seen;seen.add(base)
        out=a.output_dir/base
        if out.exists():raw=out.read_bytes()
        else:
            with urllib.request.urlopen(row['url'],timeout=60)as r:raw=r.read()
        assert len(raw)==row['bytes'] and hashlib.sha256(raw).hexdigest()==row['sha256'],base
        if not out.exists():out.write_bytes(raw)
        print('verified',base,len(raw))
