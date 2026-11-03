#!/usr/bin/env python3
"""Explicit source preparation only; no compile, signing or device actions."""
from pathlib import Path
import argparse,hashlib,json,shutil,subprocess,sys
W=Path(__file__).resolve().parent;R=W.parents[1]
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--prepare',action='store_true');p.add_argument('--out',type=Path);a=p.parse_args()
 if not a.prepare:print('INERT: explicit --prepare required');return
 if not a.out:p.error('fresh external output required')
 out=a.out.resolve()
 if out.exists() or out==R or R in out.parents:p.error('fresh external source directory required')
 pins=json.loads((W/'BASE-AND-DELTA.json').read_text())
 for n,v in pins['changes'].items():
  if sha(W/'overlay'/n)!=v['variant_sha256']:raise RuntimeError('overlay changed: '+n)
 subprocess.run([sys.executable,str(W.parent/'G1341-cb0-stall-containment/prepare.py'),'--out',str(out)],check=True)
 B=out/'experiments/G1287-cold-aperture';changes=[]
 for n,v in pins['changes'].items():
  if sha(B/n)!=v['base_sha256']:raise RuntimeError('prepared G1341 source changed: '+n)
  shutil.copyfile(W/'overlay'/n,B/n);changes.append(n)
 report={'schema':'g1343-isolated-zero-source/1','changed_files':changes,'CB0_SCTLR':'00c001e7','GMU_CB2_SCTLR':'00c00067','matched_G1341_broker_required':True,'cold_zero_idempotence_proven':False,'native_build_performed':False,'signing_performed':False,'activation_selected':False,'device_calls':0}
 (out/'G1343-PREPARED.json').write_text(json.dumps(report,indent=2)+'\n');print(out)
if __name__=='__main__':main()
