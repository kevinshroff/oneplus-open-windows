#!/usr/bin/env python3
from pathlib import Path
import os,json,subprocess
r=Path(__file__).resolve().parent
base=r.parent/'firmware-build-G203'
workspace=r/'firmware'
meta=json.loads((r.parent/'firmware-observe-G206/evidence/build-environment.json').read_text())
env={**os.environ,**meta['environment']}
env['WORKSPACE']=str(workspace);env['CONF_PATH']=str(workspace/'Conf')
env['PACKAGES_PATH']=':'.join(map(str,[workspace,base/'source',base/'source/MU_BASECORE',base/'source/Platforms']))
env['PATH']=':'.join(map(str,[base/'venv/bin',base/'toolchain/bin',base/'source/MU_BASECORE/BaseTools/BinWrappers/PosixLike',base/'source/MU_BASECORE/BaseTools/Source/C/bin']))+':/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin'
cmd=[str(base/'source/MU_BASECORE/BaseTools/BinWrappers/PosixLike/build'),'-p','G290Pkg/G535Gpu.dsc','-a','AARCH64','-b','DEBUG','-t','CLANGPDB','-n','4']
with (r/'dxe-build.log').open('w')as out:p=subprocess.run(cmd,cwd=workspace,env=env,stdout=out,stderr=out)
(r/'DXE-BUILD.json').write_text(json.dumps({'command':cmd,'exit_code':p.returncode},indent=2))
print(p.returncode);raise SystemExit(p.returncode)
