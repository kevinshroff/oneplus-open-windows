#!/usr/bin/env python3
"""Compile actual native witness/FirstUseFrame with scalar fixtures; offline only."""
from pathlib import Path
import argparse,hashlib,json,re,subprocess,tempfile
W=Path(__file__).resolve().parent;B=W.parent/'G1287-cold-aperture';R=B/'reference/runtime'
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--cc',default='clang');a=p.parse_args()
native=(B/'source/owner/gpu_cp_native.c').read_text()
first=native[native.index('static NTSTATUS FirstUseFrame('):native.index('#if OGO_GPU_PRE_RELEASE_WITNESS')]
assert first.endswith('}\n')
with tempfile.TemporaryDirectory(prefix='g1325-') as tmp:
 out=Path(tmp);(out/'actual_first_use.inc').write_text(first)
 cold=(B/'source/owner/gpu_cp_translate.c').read_text()
 (out/'actual_cold_current.inc').write_text(cold[cold.index('static NTSTATUS Current'):cold.index('static NTSTATUS Read')])
 cmd=[a.cc,'-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-fno-sanitize-recover=all','-DOGO_GPU_PRE_RELEASE_WITNESS=1','-I'+str(R),'-I'+str(out),str(W/'tests/test_witness.c'),'-o',str(out/'test')]
 subprocess.run(cmd,check=True);res=json.loads(subprocess.run([str(out/'test')],check=True,text=True,capture_output=True).stdout)
 for mode in ('2','-1'):
  q=subprocess.run([a.cc,'-x','c','-fsyntax-only','-DOGO_GPU_PRE_RELEASE_WITNESS='+mode,'-include',str(R/'g1325_witness.h'),'-'],input='',capture_output=True,text=True)
  assert q.returncode and 'must be exactly 0 or 1' in q.stderr
 # Preprocess entire real owner body with only dependency includes suppressed.
 # Exact default/0 token equality against the body with BOTH new seams removed.
 # This is compiler-input parity, not a substitute for native COFF qualification.
 dependencyless=re.sub(r'^#include .*$', '',native,flags=re.M)
 baseline=re.sub(r'^#if OGO_GPU_PRE_RELEASE_WITNESS\n.*?^#endif\n','',dependencyless,flags=re.M|re.S)
 def pp(src,mode):
  return subprocess.run([a.cc,'-E','-P','-x','c','-I'+str(R),'-include',str(R/'g1325_witness.h')]+([] if mode is None else ['-DOGO_GPU_PRE_RELEASE_WITNESS='+mode])+['-'],input=src,text=True,capture_output=True,check=True).stdout
 assert pp(dependencyless,None)==pp(dependencyless,'0')==pp(baseline,'0')
 header=(B/'source/gpu_cp_native.h').read_text()
 header=re.sub(r'^#include .*$', '',header,flags=re.M)
 headerbase=re.sub(r'^#if OGO_GPU_PRE_RELEASE_WITNESS\n.*?^#endif\n','',header,flags=re.M|re.S)
 assert pp(header,None)==pp(header,'0')==pp(headerbase,'0')
 # The common CP header is included by unrelated owner TUs. Option1 must not
 # produce unused-static warnings when its helper implementations are unused.
 unrelated=out/'unrelated.c'
 unrelated.write_text('#include <stdint.h>\ntypedef uint32_t ULONG;typedef uint64_t ULONGLONG;\n#include "g1325_witness.h"\nint unrelated(void){return 0;}\n')
 subprocess.run([a.cc,'-std=c11','-Wall','-Wextra','-Werror','-DOGO_GPU_PRE_RELEASE_WITNESS=1','-I'+str(R),'-c',str(unrelated),'-o',str(out/'unrelated.o')],check=True)
 # Historical packagers must reject an intentional-stop receipt before any
 # object/input processing. These fixtures intentionally contain no objects.
 for variant in ('G1318-secvid-zero-stores','G1322-gpu-mmio-mapping'):
  build=out/variant;build.mkdir();dest=out/(variant+'.zip')
  for receipt in ({'pre_release_witness':True},{'c_flags':['-DOGO_GPU_PRE_RELEASE_WITNESS=1']}):
   (build/'OWNER-COMPILE.json').write_text(json.dumps(receipt))
   q=subprocess.run(['python3',str(W.parent/variant/'package_native.py'),'--build-dir',str(build),'--out',str(dest)],capture_output=True,text=True)
   assert q.returncode and 'G1325 witness stop is not' in q.stderr and not dest.exists()
 # Original cold mutation/read guard still forbids accesses after Power.attempted.
 cold=(B/'source/owner/gpu_cp_translate.c').read_text()
 assert 'c->Run.Power.attempted' in cold[cold.index('static NTSTATUS Current'):cold.index('static NTSTATUS Read')]
 assert native.index('G1325StopBeforeRelease(p)')<native.index('c->FirstUseConsumed=TRUE')
 adapter=(R/'g1325_witness_native.inc').read_text()
 assert 'WRITE_REGISTER' not in adapter and 'MmMapIoSpace' not in adapter
 builder=(W.parent/'G1311-gpu-nonsecure-va/compile_owner.py').read_text()
 assert "if a.pre_release_witness:args+=['-DOGO_GPU_PRE_RELEASE_WITNESS=1']" in builder
 res.update(ASan_UBSan=True,invalid_options=2,unrelated_TU_header_Werror=True,historical_packager_refusals=4,default_and_zero_preprocessed_body_and_layout_parity=True,native_COFF_parity='not run',original_cold_power_guard_present=True,no_native_build_or_hardware=True)
 print(json.dumps(res,indent=2))
