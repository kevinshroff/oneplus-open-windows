"""Build only G1245 DXE locally when root explicitly selects --build. No image packaging."""
from pathlib import Path
import argparse,json,os,subprocess
H=Path(__file__).resolve().parent;R=H.parents[1]
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--build',action='store_true');a=p.parse_args()
 if not a.build:print('Inert: review source, then root may explicitly pass --build.');return
 B=R/'work/firmware-build-G203';meta=json.loads((R/'work/firmware-observe-G206/evidence/build-environment.json').read_text())
 env={**os.environ,**meta['environment']};env['WORKSPACE']=str(H);env['CONF_PATH']=str(H/'Conf');env['PACKAGES_PATH']=':'.join(map(str,[H,B/'source',B/'source/MU_BASECORE',B/'source/Platforms']))
 env['PATH']=':'.join(map(str,[B/'venv/bin',B/'toolchain/bin',B/'source/MU_BASECORE/BaseTools/BinWrappers/PosixLike',B/'source/MU_BASECORE/BaseTools/Source/C/bin']))+':/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin'
 cmd=[str(B/'source/MU_BASECORE/BaseTools/BinWrappers/PosixLike/build'),'-p','QueryPkg/Query.dsc','-a','AARCH64','-b','DEBUG','-t','CLANGPDB','-n','4']
 with (H/'dxe-build.log').open('x') as f:r=subprocess.run(cmd,cwd=H,env=env,stdout=f,stderr=f)
 (H/'BUILD-RESULT.json').write_text(json.dumps({'command':cmd,'exit_code':r.returncode,'image_packaged':False,'target_actions':0},indent=2)+'\n');raise SystemExit(r.returncode)
if __name__=='__main__':main()
