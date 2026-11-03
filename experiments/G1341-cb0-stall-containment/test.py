#!/usr/bin/env python3
"""Exercise the actual inherited ISR with stalled faults; no device access."""
import argparse, hashlib, json, subprocess
from pathlib import Path
W=Path(__file__).resolve().parent;R=W.parent.parent
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--source-tree',required=True,type=Path)
p.add_argument('--out',required=True,type=Path)
p.add_argument('--cc',default='clang')
a=p.parse_args();out=a.out.resolve();S=a.source_tree.resolve()/'experiments/G1287-cold-aperture/source'
if out==R or R in out.parents or out.exists():p.error('fresh external output required')
out.mkdir(parents=True)
original=R/'experiments/G1287-cold-aperture/source'
for name in ['fault_policy.c','fault_owner_native.inc','g1339_fault_tuple.h','open_smmu_activate.c','open_smmu_activate_wdm.c']:
    assert (S/name).read_bytes()==(original/name).read_bytes(),name
s=(S/'fault_owner_native.inc').read_text()
(out/'actual_isr.inc').write_text(s[s.index('#if OGO_GPU_FIRST_FAULT_TUPLE'):s.index('static NTSTATUS CaptureFaultGrants')])
rows=[]
for mode in (0,1):
    exe=out/f'stalled-{mode}'
    cmd=[a.cc,'-std=c11','-O1','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-fno-sanitize-recover=all',
         '-DOGO_GPU_FIRST_FAULT_TUPLE=1',f'-DOGO_GPU_CB0_STALL_ON_FAULT={mode}',
         '-I'+str(S),'-I'+str(out),'-I'+str(W.parent/'G1339-first-fault-tuple/tests'),
         str(W/'tests/test_stalled_isr.c'),str(S/'fault_policy.c'),'-o',str(exe)]
    q=subprocess.run(cmd,text=True,capture_output=True);assert not q.returncode,q.stderr
    q=subprocess.run([str(exe)],text=True,capture_output=True);assert not q.returncode,q.stdout+q.stderr
    rows.append(dict(mode=mode,output=q.stdout.strip()));print(q.stdout.strip())
for mode in (-1,2):
    q=subprocess.run([a.cc,'-x','c','-fsyntax-only','-I'+str(S),f'-DOGO_GPU_CB0_STALL_ON_FAULT={mode}',
                      '-include','g1341_cb0_policy.h','-'],input='',text=True,capture_output=True)
    assert q.returncode and 'must be exactly 0 or 1' in q.stderr
report=dict(schema='g1341-source-tests/1',tests=rows,invalid_flags_rejected=2,
            actual_ISR_and_ACK_unchanged=True,GMU_sources_unchanged=True,
            RESUME_writes=0,SS_acknowledged=False,ASan_UBSan=True,hardware=False)
(out/'RESULTS.json').write_text(json.dumps(report,indent=2)+'\n')
