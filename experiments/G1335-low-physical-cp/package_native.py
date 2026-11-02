#!/usr/bin/env python3
"""Freeze public source + 35 reviewed-input COFF objects for external native link."""
import argparse,hashlib,json,zipfile
from pathlib import Path
W=Path(__file__).resolve().parent;REPO=W.parent.parent
sha=lambda b:hashlib.sha256(b).hexdigest()
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--build-dir',required=True,type=Path)
p.add_argument('--out',required=True,type=Path)
p.add_argument('--default-off-build',required=True,type=Path)
p.add_argument('--source-tree',required=True,type=Path)
p.add_argument('--baseline-build',required=True,type=Path)
a=p.parse_args();build=a.build_dir.resolve();dest=a.out.resolve()
if REPO==dest or REPO in dest.parents:p.error('artifact must remain outside public repository')
source=a.source_tree.resolve();prepared=json.loads((source/'PREPARED.json').read_text())
if prepared['patch_sha256']!=sha((W/'source.patch').read_bytes()) or prepared['allocation_header_sha256']!=sha((W/'ogo_gpu_allocation.h').read_bytes()) or prepared['base_pins']!=json.loads((W/'BASE-PINS.json').read_text()):raise RuntimeError('wrong prepared source copy')
for name,h in prepared['base_pins'].items():
 if sha((REPO/name).read_bytes())!=h:raise RuntimeError('authoritative base changed')
report=json.loads((build/'OWNER-COMPILE.json').read_text())
if report['layout']!='nonsecure64' or report.get('secvid_zero_stores') is not True or len(report['objects'])!=35:raise RuntimeError('exact G1335 build required')
if report.get('pre_release_witness') is not False or '-DOGO_GPU_PRE_RELEASE_WITNESS=1' in report['c_flags']:raise RuntimeError('normal existing CP sequence required')
if report.get('gpu_mmio_writecombine') is not False or '-DOGO_GPU_MMIO_WRITECOMBINE=1' in report['c_flags']:raise RuntimeError('G1335 uses the prior non-WC mapping baseline')
if '-DOGO_GPU_SECVID_ZERO_STORES=1' not in report['c_flags'] or '-DOGO_GPU_NONSECURE64_VA=1' not in report['c_flags']:raise RuntimeError('wrong baseline flags')
if report.get('sqe_low_iova') is not False or '-DOGO_GPU_SQE_LOW_IOVA=1' in report['c_flags']:raise RuntimeError('original G1325 SQE IOVA required')
if report.get('gpu_low_physical') is not True or '-DOGO_GPU_LOW_PHYSICAL=1' not in report['c_flags']:raise RuntimeError('explicit CP-only low physical required')
files={}
default=json.loads((a.default_off_build/'OWNER-COMPILE.json').read_text())
for key in ['layout','secvid_zero_stores','gpu_mmio_writecombine','pre_release_witness','source_pins','compiler_version','sqe_low_iova']:
 if default[key]!=report[key]:raise RuntimeError('default-off comparison differs: '+key)
if default.get('gpu_low_physical') is not False or '-DOGO_GPU_LOW_PHYSICAL=1' in default['c_flags']:raise RuntimeError('comparison must be low physical off')
if report['c_flags']!=default['c_flags']+['-DOGO_GPU_LOW_PHYSICAL=1']:raise RuntimeError('unexpected compile flag difference')
dh={r['object']:r['sha256'] for r in default['objects']}
changed=[r['object'] for r in report['objects'] if dh.get(r['object'])!=r['sha256']]
if len(dh)!=35 or len({r['object'] for r in report['objects']})!=35 or {r['object'] for r in report['objects']}!=set(dh) or changed!=['11_open_smmu_inactive.obj','43_gpu_cp_native.obj']:raise RuntimeError('unexpected COFF differences')
for row in default['objects']:
 b=(a.default_off_build/row['object']).read_bytes()
 if sha(b)!=row['sha256']:raise RuntimeError('default-off object changed')
baseline=json.loads((a.baseline_build/'OWNER-COMPILE.json').read_text())
if {r['object']:r['sha256'] for r in baseline['objects']}!=dh:raise RuntimeError('default-off differs from actual G1325 baseline')
files['BASELINE-COMPILE.json']=(a.baseline_build/'OWNER-COMPILE.json').read_bytes()
files['SOURCE-COPY-PREPARED.json']=(source/'PREPARED.json').read_bytes()
files['DEFAULT-OFF-COMPILE.json']=(a.default_off_build/'OWNER-COMPILE.json').read_bytes()
files['COFF-COMPARISON.json']=(json.dumps(dict(default_off_objects=35,changed_objects=changed,native_evidence=False),indent=2)+'\n').encode()
for row in report['objects']:
 name=row['object'];b=(build/name).read_bytes()
 if Path(name).name!=name or sha(b)!=row['sha256'] or b[:2]!=bytes.fromhex('64aa'):raise RuntimeError('object changed')
 files[name]=b
for name in ['OWNER-COMPILE.json','owner-link.rsp','owner-objects.rsp','owner-libraries.rsp']:files[name]=(build/name).read_bytes()
for name,h in report['source_pins'].items():
 src=(source/name).resolve()
 if source not in src.parents or sha(src.read_bytes())!=h:raise RuntimeError('public source changed since compile')
 files['source-tree/'+name]=src.read_bytes()
# Include the candidate diff/test recipe and patched compiler/link inventory.
for src in sorted(W.rglob('*')):
 if src.is_file() and '__pycache__' not in src.parts and src.name!='VALIDATION.json':files['candidate/'+str(src.relative_to(W))]=src.read_bytes()
for name in ['compile_owner.py','OWNER-SOURCES.json','OWNER-LINK.json']:
 files['source-tree/experiments/G1311-gpu-nonsecure-va/'+name]=(source/'experiments/G1311-gpu-nonsecure-va'/name).read_bytes()
policy=json.loads((source/'experiments/G1311-gpu-nonsecure-va/OWNER-LINK.json').read_text())
if sha((source/'experiments/G1311-gpu-nonsecure-va/OWNER-LINK.json').read_bytes())!=report['link_policy_sha256']:raise RuntimeError('link policy changed')
for name,lines in [('owner-objects.rsp',[r['object'] for r in report['objects']]),('owner-libraries.rsp',policy['libraries']),('owner-link.rsp',policy['options']+['/out:'+policy['output'],'/map:'+policy['map']]+[r['object'] for r in report['objects']]+policy['libraries'])]:
 if (build/name).read_text()!='\n'.join(lines)+'\n':raise RuntimeError('response file changed: '+name)
manifest=dict(schema='g1335-owner-native-inputs/1',owner_objects=35,layout='nonsecure64',secvid_zero_stores=True,gpu_mmio_writecombine=False,pre_release_witness=False,sqe_low_iova=False,sqe_iova=0x4000010000,gpu_low_physical=True,CP_allocation_high=0xffffffff,GMU_allocation_unchanged=True,intentional_stop_before_SQE=False,
              native_link_performed=False,signing_performed=False,hardware_qualified=False,activation_selected=False,
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
