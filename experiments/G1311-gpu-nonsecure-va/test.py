#!/usr/bin/env python3
"""Offline sanitizer qualification. Outputs only to an explicit/temporary folder."""
import argparse, hashlib, json, os, subprocess, tempfile
from pathlib import Path
W=Path(__file__).resolve().parent
BASE=W.parent/'G1287-cold-aperture'
R=BASE/'reference/runtime'
V=BASE/'reference/inactive/source/vendor'
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--cc',default=os.environ.get('CC','clang'))
p.add_argument('--out',type=Path)
a=p.parse_args()
tmp=None
if a.out is None:
    tmp=tempfile.TemporaryDirectory(prefix='g1311-');out=Path(tmp.name)
else:
    out=a.out.resolve();out.mkdir(parents=True,exist_ok=True)
rows=[]
for mode in (0,1):
    for name,inputs in (
        ('cp_fields',[W/'tests/test_cp_fields.c',R/'g433_cp.c',R/'vendor/AdrenoPM4.c']),
        ('tables',[W/'tests/test_tables.c',V/'ArmSmmu4K.c',V/'ArmSmmu4KAuditInactive.c'])):
        exe=out/f'{name}-{mode}'
        argv=[a.cc,'-std=c11','-O1','-g','-Wall','-Wextra','-Werror',
              '-fsanitize=address,undefined','-fno-sanitize-recover=all',
              f'-DOGO_GPU_NONSECURE64_VA={mode}',
              '-I'+str(BASE/'source/owner'),'-I'+str(R),'-I'+str(V),
              *map(str,inputs),'-o',str(exe)]
        subprocess.run(argv,check=True)
        result=subprocess.run([str(exe)],check=True,text=True,capture_output=True)
        print(f'{name}-{mode}: {result.stdout.strip()}')
        rows.append(dict(name=name,mode=mode,result=json.loads(result.stdout),
                         source_sha256={str(x.relative_to(W.parent.parent)):hashlib.sha256(x.read_bytes()).hexdigest() for x in inputs}))
# Invalid selection fails at compile time, before an owner can be emitted.
for mode in ('2','-1'):
    q=subprocess.run([a.cc,'-x','c','-fsyntax-only',f'-DOGO_GPU_NONSECURE64_VA={mode}',
                      '-include',str(BASE/'source/owner/gpu_va_layout.h'),'-'],input='',text=True,capture_output=True)
    assert q.returncode!=0 and 'must be exactly 0 or 1' in q.stderr,q.stderr
report=dict(native_evidence=False,ASan_UBSan=True,tests=rows,invalid_selection_cases=2)
if a.out is not None:(out/'RESULTS.json').write_text(json.dumps(report,indent=2)+'\n')
if tmp:tmp.cleanup()
