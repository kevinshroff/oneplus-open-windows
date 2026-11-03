#!/usr/bin/env python3
"""Explicit offline source overlay only; no compile/link/sign/firmware/target calls."""
from pathlib import Path
import argparse,hashlib,json,shutil,subprocess,sys
W=Path(__file__).resolve().parent;R=W.parents[1]
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--prepare',action='store_true');p.add_argument('--out',type=Path);a=p.parse_args()
 if not a.prepare:print('INERT: explicit --prepare required');return
 if not a.out:p.error('fresh external output required')
 out=a.out.resolve()
 if out.exists()or out==R or R in out.parents:p.error('fresh external output required')
 m=json.loads((W/'BASE-AND-DELTA.json').read_text());src=W/'overlay'/m['changed_source'];assert sha(src)==m['variant_sha256']
 subprocess.run([sys.executable,str(W.parent/'G1347/prepare.py'),'--prepare','--out',str(out)],check=True)
 b=out/'experiments/G1287-cold-aperture';f=b/m['changed_source'];assert sha(f)==m['base_sha256'];shutil.copyfile(src,f)
 (out/'G1348-PREPARED.json').write_text(json.dumps({'schema':'G1348-existing-CB0-write-map-source/1','changed_source':m['changed_source'],'existing_CB0_RW_map_only':True,'owner_recompile_required':False,'firmware_rebuild_required':False,'reused_owner_sha256':m['signed_owner_reused_sha256'],'reused_firmware_sha256':m['firmware_reused_sha256'],'target_calls':0,'activation_selected':False},indent=2)+'\n');print(out)
if __name__=='__main__':main()
