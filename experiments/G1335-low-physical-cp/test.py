#!/usr/bin/env python3
"""Run actual inactive allocator against a bounded CPU allocation shim."""
import argparse,json,subprocess
from pathlib import Path
W=Path(__file__).resolve().parent
p=argparse.ArgumentParser();p.add_argument('--source-tree',required=True,type=Path);p.add_argument('--out',required=True,type=Path);p.add_argument('--cc',default='clang');a=p.parse_args();out=a.out.resolve();out.mkdir(parents=True,exist_ok=True)
S=a.source_tree.resolve()/'experiments/G1287-cold-aperture';I=S/'reference/inactive/source';rows=[]
for mode in (0,1):
 exe=out/f'allocator-{mode}';cmd=[a.cc,'-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-fno-sanitize-recover=all',f'-DOGO_GPU_LOW_PHYSICAL={mode}','-I'+str(W/'tests'),'-I'+str(I),str(W/'tests/test_allocator.c'),str(I/'open_smmu_inactive.c'),str(I/'vendor/ArmSmmu4K.c'),str(I/'vendor/ArmSmmu4KAuditInactive.c'),'-o',str(exe)]
 subprocess.run(cmd,check=True);q=subprocess.run([str(exe)],capture_output=True,text=True);assert q.returncode==0,q.stdout+q.stderr;print(mode,q.stdout.strip());rows.append(dict(low_physical=bool(mode),boundary_cases=9,generic_high_PA_preserved=True,result='pass'))
for mode in ('-1','2'):
 q=subprocess.run([a.cc,'-x','c','-fsyntax-only',f'-DOGO_GPU_LOW_PHYSICAL={mode}','-include',str(W/'ogo_gpu_allocation.h'),'-'],input='',text=True,capture_output=True);assert q.returncode!=0 and 'must be exactly 0 or 1' in q.stderr
(out/'RESULTS.json').write_text(json.dumps(dict(native_evidence=False,ASan_UBSan=True,tests=rows,invalid_selectors=2),indent=2)+'\n')
