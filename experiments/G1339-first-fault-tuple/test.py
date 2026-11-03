#!/usr/bin/env python3
"""Compile the actual integrated ISR slice with a CPU MMIO shim; never hardware."""
import argparse,hashlib,json,re,subprocess
from pathlib import Path
W=Path(__file__).resolve().parent;R=W.parent.parent;S=W.parent/'G1287-cold-aperture/source'
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',required=True,type=Path);p.add_argument('--cc',default='clang');a=p.parse_args();out=a.out.resolve()
if out==R or R in out.parents:p.error('output must be outside public checkout')
out.mkdir(parents=True,exist_ok=True)
s=(S/'fault_owner_native.inc').read_text();start=s.index('#if OGO_GPU_FIRST_FAULT_TUPLE');end=s.index('static NTSTATUS CaptureFaultGrants');fragment=s[start:end];actual=out/'actual_isr.inc';actual.write_text(fragment)
def run(args,**kw):
 q=subprocess.run(args,text=True,capture_output=True,**kw)
 if q.returncode:raise RuntimeError(q.stdout+q.stderr)
 return q
# Token parity covers the actual native ISR with default disabled. It is not a
# native broker COFF equivalence claim; full genuine-header compile is separate.
tokens=[]
for f in [actual,W/'tests/baseline_isr.inc']:
 q=run([a.cc,'-E','-P','-x','c','-DOGO_GPU_FIRST_FAULT_TUPLE=0',str(f)]);tokens.append(re.sub(r'\s+','',q.stdout))
assert tokens[0]==tokens[1],'default-off ISR tokens changed'
rows=[]
for mode in (0,1):
 exe=out/f'isr-{mode}';cmd=[a.cc,'-std=c11','-O1','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-fno-sanitize-recover=all',f'-DOGO_GPU_FIRST_FAULT_TUPLE={mode}','-I'+str(S),'-I'+str(out),str(W/'tests/test_isr.c'),str(S/'fault_policy.c'),'-o',str(exe)]
 q=run(cmd);assert not q.stderr,q.stderr;q=run([str(exe)]);print(q.stdout.strip());rows.append(dict(option=mode,output=q.stdout.strip(),ASan_UBSan=True))
for mode in ('-1','2'):
 q=subprocess.run([a.cc,'-x','c','-fsyntax-only','-I'+str(S),f'-DOGO_GPU_FIRST_FAULT_TUPLE={mode}','-include','fault_policy.h','-'],input='',text=True,capture_output=True);assert q.returncode and 'must be exactly 0 or 1' in q.stderr
pins={str(f.relative_to(R)):hashlib.sha256(f.read_bytes()).hexdigest() for f in [S/'fault_owner_native.inc',S/'fault_owner.h',S/'fault_policy.h',S/'fault_policy.c',S/'g1339_fault_tuple.h']}
report=dict(schema='g1339-source-tests/1',default_off_ISR_token_parity=True,source_pins=pins,tests=rows,invalid_selectors=2,native_broker_COFF_compiled=False,hardware=False,activation=False)
(out/'RESULTS.json').write_text(json.dumps(report,indent=2)+'\n')
