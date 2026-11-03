#!/usr/bin/env python3
"""Local authored-core behavioral tests; no firmware/native-driver build or target."""
from pathlib import Path
import argparse,json,subprocess,tempfile,hashlib
W=Path(__file__).resolve().parent
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--cc',default='clang');a=p.parse_args()
m=json.loads((W/'BASE-AND-DELTA.json').read_text())
for n,v in m['changes'].items():assert hashlib.sha256((W/'overlay'/n).read_bytes()).hexdigest()==v['variant_sha256']
base=(W.parents[1]/'firmware/G991/Mmu1.asl').read_text();new=(W/'firmware/Mmu1.asl').read_text();line='                Memory32Fixed (ReadWrite, 0x03DE8000, 0x00001000, QTBR)\n';assert new.count(line)==1 and new.replace(line,'')==base
owner=(W/'overlay/source/owner/gpu_cp_native.c').read_text();assert owner.index('Api.QtbOnce(')<owner.index('CpPoint(p,"Configure begin"');assert 'goto leave;'in owner[owner.index('Api.QtbOnce('):owner.index('CpPoint(p,"Configure begin"')]
with tempfile.TemporaryDirectory(prefix='qtb-host-')as t:
 for flag in [0,1]:
  common=[a.cc,'-std=c11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',f'-DOPEN_QTB_WITNESS={flag}']
  exe=Path(t)/f'core{flag}';subprocess.run(common+['-Wno-unused-function','-I'+str(W/'overlay/source'),str(W/'overlay/source/qtb_once.c'),str(W/'tests/test_qtb.c'),'-o',str(exe)],check=True);subprocess.run([str(exe)],check=True)
  exe=Path(t)/f'vote{flag}';subprocess.run(common+['-Wno-unused-variable',str(W/'tests/test_vote.c'),'-o',str(exe)],check=True)
  for mode in ([0,1,2,3]if flag else[0]):subprocess.run([str(exe),str(mode)],check=True)
print('PASS: isolated grant + terminal seam + disabled/enabled transaction/vote semantics; no native link/firmware build/hardware')
