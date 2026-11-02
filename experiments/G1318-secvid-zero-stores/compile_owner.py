#!/usr/bin/env python3
"""Full 35-object G1318 owner compile: fixed nonsecure64 + four zero stores."""
import argparse,subprocess,sys
from pathlib import Path
W=Path(__file__).resolve().parent
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--cc',required=True)
p.add_argument('--system-include',required=True,type=Path,action='append')
p.add_argument('--out',required=True,type=Path)
a=p.parse_args()
args=[sys.executable,str(W.parent/'G1311-gpu-nonsecure-va/compile_owner.py'),
      '--layout','nonsecure64','--secvid-zero-stores','--cc',a.cc,'--out',str(a.out)]
for x in a.system_include:args+=['--system-include',str(x)]
subprocess.run(args,check=True)
