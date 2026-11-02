"""Verify/extract project-local pinned Microsoft headers and libraries.

No installer, registry/PATH change, native execution or signature claim.
--download explicitly allows absent package archives to be downloaded.
"""
import argparse,hashlib,json,urllib.request,zipfile
from pathlib import Path,PurePosixPath

p=argparse.ArgumentParser(description=__doc__);p.add_argument('--packages',type=Path,required=True)
p.add_argument('--output',type=Path,required=True);p.add_argument('--download',action='store_true');a=p.parse_args()
assert not a.output.exists();a.output.mkdir(parents=True)
catalog=json.loads((Path(__file__).parent/'WDK-packages.json').read_text());records=[]
for row in catalog['packages']:
    p=a.packages/(row['name']+'.nupkg')
    if not p.exists():
        assert a.download,'Missing package; --download is required to fetch it'
        p.parent.mkdir(parents=True,exist_ok=True)
        with urllib.request.urlopen(row['url'],timeout=60) as r,p.open('xb') as out:
            size=0
            while True:
                b=r.read(1024*1024)
                if not b:break
                size+=len(b);assert size<=row['bytes'];out.write(b)
    assert p.stat().st_size==row['bytes']
    assert hashlib.sha256(p.read_bytes()).hexdigest()==row['sha256']
    prefix='wdk' if '.wdk.' in row['name'] else 'sdk';selected=[]
    with zipfile.ZipFile(p) as z:
        for info in z.infolist():
            n=info.filename
            if prefix=='wdk':
                take=n.startswith(('c/Include/10.0.26100.0/km/','c/Include/wdf/kmdf/1.15/')) or n in [
                    'c/Lib/10.0.26100.0/km/ARM64/ntoskrnl.lib',
                    'c/Lib/wdf/kmdf/ARM64/1.15/wdfdriverentry.lib','c/Lib/wdf/kmdf/ARM64/1.15/wdfldr.lib']
            elif row['name']=='microsoft.windows.sdk.cpp':
                take=n.startswith(('c/Include/10.0.26100.0/shared/','c/Include/10.0.26100.0/ucrt/'))
            else:take=False
            if not take or info.is_dir():continue
            q=PurePosixPath(n);assert not q.is_absolute() and '..' not in q.parts
            assert info.file_size<=100*1024*1024
            b=z.read(info);out=a.output/prefix/n;out.parent.mkdir(parents=True,exist_ok=True)
            if out.exists():assert out.read_bytes()==b
            else:out.write_bytes(b)
            selected.append({'path':str(out.relative_to(a.output)),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()})
    records.append({'package':row['name'],'package_sha256':row['sha256'],'files':selected})
(a.output/'extraction.json').write_text(json.dumps(records,indent=2)+'\n')
print(json.dumps({'files':sum(len(r['files']) for r in records),'project_local_extraction_only':True}))
