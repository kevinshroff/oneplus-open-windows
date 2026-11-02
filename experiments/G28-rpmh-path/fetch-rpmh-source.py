"""Reacquire the six pinned public RPMh files; download only, no execution."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import urllib.request

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--catalog',type=Path,required=True)
p.add_argument('--output',type=Path,required=True)
a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
catalog=json.loads(a.catalog.read_text())
assert catalog['repository']=='OnePlusOSS/android_kernel_oneplus_sm8550'
assert catalog['commit']=='c87f74901db572a762241d6dfcacc42dbdd9f798'
assert len(catalog['files'])==6
rows=[]
for row in catalog['files']:
    path=PurePosixPath(row['path']);assert not path.is_absolute()and'..'not in path.parts
    url='https://raw.githubusercontent.com/'+catalog['repository']+'/'+catalog['commit']+'/'+str(path)
    assert row['url']==url and 0<row['bytes']<2000000
    with urllib.request.urlopen(url,timeout=30)as response:data=response.read(row['bytes']+1)
    assert len(data)==row['bytes']and hashlib.sha256(data).hexdigest()==row['sha256']
    out=a.output/path;out.parent.mkdir(parents=True,exist_ok=True);out.write_bytes(data);rows.append(row)
(a.output/'fetch-receipt.json').write_text(json.dumps({'files':rows,'all_hashes_match':True,'code_executed':False},indent=2)+'\n')
print(json.dumps({'files':len(rows),'all_hashes_match':True}))
