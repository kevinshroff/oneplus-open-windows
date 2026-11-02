#!/usr/bin/env python3
"""Freeze public source + 35 reviewed-input COFF objects for external native link."""
import argparse,hashlib,json,zipfile
from pathlib import Path
W=Path(__file__).resolve().parent;REPO=W.parent.parent
sha=lambda b:hashlib.sha256(b).hexdigest()
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--build-dir',required=True,type=Path)
p.add_argument('--out',required=True,type=Path)
a=p.parse_args();build=a.build_dir.resolve();dest=a.out.resolve()
if REPO==dest or REPO in dest.parents:p.error('artifact must remain outside public repository')
report=json.loads((build/'OWNER-COMPILE.json').read_text())
if report['layout']!='nonsecure64' or report.get('secvid_zero_stores') is not True or len(report['objects'])!=35:raise RuntimeError('exact G1322 build required')
if report.get('gpu_mmio_writecombine') is not True or '-DOGO_GPU_MMIO_WRITECOMBINE=1' not in report['c_flags']:raise RuntimeError('exact GPU mapping request required')
if '-DOGO_GPU_SECVID_ZERO_STORES=1' not in report['c_flags'] or '-DOGO_GPU_NONSECURE64_VA=1' not in report['c_flags']:raise RuntimeError('wrong compile flags')
files={}
for row in report['objects']:
 name=row['object'];b=(build/name).read_bytes()
 if Path(name).name!=name or sha(b)!=row['sha256'] or b[:2]!=bytes.fromhex('64aa'):raise RuntimeError('object changed')
 files[name]=b
for name in ['OWNER-COMPILE.json','owner-link.rsp','owner-objects.rsp','owner-libraries.rsp']:files[name]=(build/name).read_bytes()
for name,h in report['source_pins'].items():
 src=(REPO/name).resolve()
 if REPO not in src.parents or sha(src.read_bytes())!=h:raise RuntimeError('public source changed since compile')
 files['source-tree/'+name]=src.read_bytes()
for folder in [W,W.parent/'G1311-gpu-nonsecure-va']:
 for name in ['compile_owner.py','OWNER-SOURCES.json','OWNER-LINK.json','package_native.py','test.py','README.md']:
  src=folder/name
  if src.is_file():files['source-tree/'+str(src.relative_to(REPO))]=src.read_bytes()
manifest=dict(schema='g1322-owner-native-inputs/1',owner_objects=35,layout='nonsecure64',secvid_zero_stores=True,gpu_mmio_writecombine=True,
              native_link_performed=False,signing_performed=False,hardware_qualified=False,
              libraries_external=['ntoskrnl.lib','hal.lib','libcntpr.lib','bufferoverflowfastfailk.lib','aux_klib.lib'],
              files={n:dict(bytes=len(b),sha256=sha(b)) for n,b in sorted(files.items())})
mb=(json.dumps(manifest,indent=2)+'\n').encode();files['MANIFEST.json']=mb
with zipfile.ZipFile(dest,'x',zipfile.ZIP_DEFLATED) as z:
 for n,b in sorted(files.items()):z.writestr(n,b)
with zipfile.ZipFile(dest) as z:
 for n,b in files.items():assert sha(z.read(n))==sha(b)
result=dict(zip_sha256=sha(dest.read_bytes()),manifest_sha256=sha(mb),members=len(files),owner_objects=35,
            native_link_performed=False,signing_performed=False,hardware_qualified=False)
dest.with_suffix('.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
