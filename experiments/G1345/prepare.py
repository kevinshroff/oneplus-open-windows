#!/usr/bin/env python3
"""Explicit offline G1345 source preparation; no compile/image/stage/device calls."""
from pathlib import Path
import argparse,hashlib,json,shutil,subprocess,sys
W=Path(__file__).resolve().parent;R=W.parents[1]
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--prepare',action='store_true');p.add_argument('--out',type=Path);a=p.parse_args()
 if not a.prepare:print('INERT: explicit --prepare required');return
 if not a.out:p.error('fresh external output required')
 out=a.out.resolve()
 if out.exists()or out==R or R in out.parents:p.error('fresh output outside checkout required')
 m=json.loads((W/'BASE-AND-DELTA.json').read_text())
 for n,v in m['changes'].items():
  if sha(W/'overlay'/n)!=v['variant_sha256']:raise RuntimeError('overlay changed: '+n)
 for n,digest in m['firmware_base_pins'].items():
  if sha(R/n)!=digest:raise RuntimeError('firmware base changed: '+n)
 subprocess.run([sys.executable,str(W.parent/'G1343-zero-write-control/prepare.py'),'--prepare','--out',str(out)],check=True)
 b=out/'experiments/G1287-cold-aperture'
 for n,v in m['changes'].items():
  if v['base_sha256']is not None and sha(b/n)!=v['base_sha256']:raise RuntimeError('baseline changed: '+n)
  shutil.copyfile(W/'overlay'/n,b/n)
 # Default-off owner command line; matched broker and firmware need same macro.
 c=out/'experiments/G1311-gpu-nonsecure-va/compile_owner.py';s=c.read_text()
 a1='a=p.parse_args()';a2='for x in includes:'
 if s.count(a1)!=1 or s.count(a2)!=1:raise RuntimeError('compiler seams changed')
 s=s.replace(a1,"p.add_argument('--gpu-qtb-witness',action='store_true',help='G1345 terminal QTB witness; requires matched broker/new firmware')\n"+a1)
 s=s.replace(a2,"if a.gpu_qtb_witness:args+=['-DOPEN_QTB_WITNESS=1']\n"+a2);c.write_text(s)
 shutil.copytree(R/'firmware/G991',out/'firmware/G991')
 f=out/'firmware/G991/OpenOwnerPkg'
 for name in ['Publish.c','Publish.inf','qtb_npa_abi.h','qtb_tcu_vote.inc','QtbProviders.dec']:shutil.copyfile(W/'firmware'/name,f/name)
 shutil.copyfile(W/'firmware/Mmu1.asl',out/'firmware/G991/QtbMmu1.asl')
 (out/'G1345-PREPARED.json').write_text(json.dumps({'schema':'g1345-coupled-qtb-source/1','default_enabled':False,'macro':'OPEN_QTB_WITNESS=1','new_firmware_and_matched_pair_required':True,'firmware_aml_header_missing_until_reviewed_build':'QtbMmu1.h','native_link':False,'firmware_image_built':False,'signing':False,'hardware_selected':False},indent=2)+'\n');print(out)
if __name__=='__main__':main()
