"""Default inert. Root may compile three ARM64 COFF inputs; never links/runs a SYS."""
from pathlib import Path
import argparse,subprocess,json,hashlib
H=Path(__file__).resolve().parent;R=H.parents[1]
def main():
 p=argparse.ArgumentParser();p.add_argument('--compile-only',action='store_true');a=p.parse_args()
 if not a.compile_only:print('INERT: root-reviewed --compile-only required; no build or monitor call');return
 # Reuse exact established WDK target/options, retaining only system include roots.
 recipe=R/'work/gpu-bv-shadow-G1148/build/COMPILE.json';row=json.loads(recipe.read_text())[0];argv=row['argv'];flags=argv[argv.index('--target=aarch64-pc-windows-msvc'):argv.index('-c')];flags=[x for x in flags if not x.startswith('-I')]
 B=H/'build';B.mkdir(exist_ok=False);rows=[]
 for name in ['driver.c','query_state.c','smc_fast_info.S']:
  src=H/'source'/name;out=B/(src.stem+'.obj');cmd=[argv[0]]+(['--target=aarch64-pc-windows-msvc'] if src.suffix=='.S' else ['-I'+str(H/'source')]+flags)+['-c',str(src),'-o',str(out)]
  q=subprocess.run(cmd,capture_output=True,text=True);entry={'source':name,'command':cmd,'exit_code':q.returncode,'stderr':q.stderr,'source_sha256':hashlib.sha256(src.read_bytes()).hexdigest()}
  if q.returncode==0:
   b=out.read_bytes();assert b[:2]==b'\x64\xaa';out.write_bytes(b[:4]+bytes(4)+b[8:]);entry['object_sha256']=hashlib.sha256(out.read_bytes()).hexdigest()
  rows.append(entry)
  if q.returncode:(H/'COMPILE.json').write_text(json.dumps(rows,indent=2)+'\n');raise SystemExit(q.stderr)
 (H/'COMPILE.json').write_text(json.dumps(rows,indent=2)+'\n');print('COFF only; native MSVC link/PE review/signing remain root work. No SYS executed.')
if __name__=='__main__':main()
