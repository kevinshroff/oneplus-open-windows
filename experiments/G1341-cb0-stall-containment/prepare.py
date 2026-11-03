#!/usr/bin/env python3
"""Prepare an isolated G1335 low-PA/G1339 tuple source variant; no build or load."""
import argparse, hashlib, json, shutil, subprocess, sys
from pathlib import Path
W=Path(__file__).resolve().parent
R=W.parent.parent
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--out',required=True,type=Path)
a=p.parse_args();out=a.out.resolve()
if out==R or R in out.parents or out.exists():p.error('fresh external source directory required')
pins=json.loads((W/'BASE-PINS.json').read_text())
for name,digest in pins.items():
    if sha(R/name)!=digest:raise RuntimeError('source changed: '+name)
subprocess.run([sys.executable,str(W.parent/'G1335-low-physical-cp/prepare.py'),'--out',str(out)],check=True)
b=out/'experiments/G1287-cold-aperture'
changes=[]
for name,count in [('source/owner/gpu_cp_translate.c',2),('source/gpu_user_native.inc',2),('reference/runtime/g1325_witness.h',1)]:
    f=b/name;s=f.read_text();before=sha(f)
    import re
    s,n=re.subn(r'0x0?0?c00067u?', 'OGO_GPU_CB0_SCTLR',s)
    if n!=count:raise RuntimeError('unexpected CB0 constant count: '+name)
    f.write_text('#include "g1341_cb0_policy.h"\n'+s)
    changes.append(dict(path=name,before=before,after=sha(f)))
shutil.copyfile(W/'g1341_cb0_policy.h',b/'source/g1341_cb0_policy.h')
compiler=out/'experiments/G1311-gpu-nonsecure-va/compile_owner.py'
s=compiler.read_text()
s=s.replace('a=p.parse_args()',"p.add_argument('--gpu-cb0-stall-on-fault',action='store_true',help='G1341 matched CB0 stall profile; default off')\na=p.parse_args()",1)
s=s.replace('for x in includes:',"if a.gpu_cb0_stall_on_fault:args+=['-DOGO_GPU_CB0_STALL_ON_FAULT=1']\nfor x in includes:",1)
s=s.replace("report=dict(schema='g1311-public-owner-coff/1',","report=dict(schema='g1311-public-owner-coff/1',gpu_cb0_stall_on_fault=a.gpu_cb0_stall_on_fault,",1)
compiler.write_text(s)
report=dict(schema='g1341-isolated-source/1',base_pins=pins,changed_cb0_files=changes,
    header_sha256=sha(W/'g1341_cb0_policy.h'),default_sctlr='00c00067',selected_sctlr='00c001e7',
    selected_flag='OGO_GPU_CB0_STALL_ON_FAULT=1',broker_additional_flag='OGO_GPU_FIRST_FAULT_TUPLE=1',
    owner_required_flags=['OGO_GPU_NONSECURE64_VA=1','OGO_GPU_SECVID_ZERO_STORES=1','OGO_GPU_LOW_PHYSICAL=1'],
    GMU_context_unchanged=True,translation_attributes_unchanged=True,live_operations=0,activation_selected=False)
(out/'G1341-PREPARED.json').write_text(json.dumps(report,indent=2)+'\n')
print(out)
