#!/usr/bin/env python3
"""Prepare an external source copy only; never edits the authoritative closure."""
import argparse,hashlib,json,shutil,subprocess
from pathlib import Path
W=Path(__file__).resolve().parent;REPO=W.parent.parent
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',required=True,type=Path);a=p.parse_args();out=a.out.resolve()
if out==REPO or REPO in out.parents or out.exists():p.error('fresh external destination required')
pins=json.loads((W/'BASE-PINS.json').read_text())
for name,h in pins.items():
 if hashlib.sha256((REPO/name).read_bytes()).hexdigest()!=h:raise RuntimeError('base source changed: '+name)
out.mkdir(parents=True)
for name in ['G1287-cold-aperture','G1311-gpu-nonsecure-va']:
 shutil.copytree(W.parent/name,out/'experiments'/name,ignore=shutil.ignore_patterns('__pycache__'))
subprocess.run(['patch','--batch','-p1','-i',str(W/'source.patch')],cwd=out,check=True)
shutil.copyfile(W/'ogo_gpu_allocation.h',out/'experiments/G1287-cold-aperture/reference/inactive/source/ogo_gpu_allocation.h')
report={'schema':'g1335-source-copy/1','source_only':True,'base_pins':pins,'patch_sha256':hashlib.sha256((W/'source.patch').read_bytes()).hexdigest(),'allocation_header_sha256':hashlib.sha256((W/'ogo_gpu_allocation.h').read_bytes()).hexdigest(),'activation_approved':False,'hardware_qualified':False}
(out/'PREPARED.json').write_text(json.dumps(report,indent=2)+'\n');print(out)
