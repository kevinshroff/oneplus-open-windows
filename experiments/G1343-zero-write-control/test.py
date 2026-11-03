#!/usr/bin/env python3
"""Run actual zero-only G433 core against host mock IO, never native hardware."""
import argparse,hashlib,json,subprocess
from pathlib import Path
W=Path(__file__).resolve().parent
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source-tree',required=True,type=Path);p.add_argument('--out',required=True,type=Path);a=p.parse_args();B=a.source_tree/'experiments/G1287-cold-aperture';out=a.out
 if out.exists():p.error('fresh external host output required')
 if out.resolve()==W.parents[1] or W.parents[1] in out.resolve().parents:p.error('host output outside public repository required')
 pins=json.loads((W/'BASE-AND-DELTA.json').read_text())
 for n,v in pins['changes'].items():assert sha(B/n)==v['variant_sha256']
 out.mkdir(parents=True);runtime=B/'reference/runtime';argv=['clang','-std=c11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-fno-sanitize-recover=all','-I'+str(runtime),str(W/'tests/test_zero_core.c'),str(runtime/'g433_cp.c'),str(runtime/'vendor/AdrenoPM4.c'),'-o',str(out/'test_zero_core')];subprocess.run(argv,check=True);q=subprocess.run([str(out/'test_zero_core')],check=True,capture_output=True,text=True)
 (out/'RESULT.json').write_text(json.dumps({'schema':'g1343-zero-host-model/1','stdout':q.stdout.strip(),'ASan_UBSan':'pass','native_ABI_or_MMIO_evidence':False,'device_calls':0},indent=2)+'\n');print(q.stdout,end='')
if __name__=='__main__':main()
