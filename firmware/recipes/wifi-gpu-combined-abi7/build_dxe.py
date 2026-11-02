#!/usr/bin/env python3
"""G735 standalone DXE build (patched WlanBringupG622 with SMMU identity)."""
from pathlib import Path
import os,json,subprocess,hashlib
r=Path(__file__).resolve().parent
root=r.parents[1]
base=root/'work/firmware-build-G203'
workspace=r/'firmware'
meta=json.loads((root/'work/firmware-observe-G206/evidence/build-environment.json').read_text())
env={**os.environ,**{k:v for k,v in meta['environment'].items() if k not in ('HOME','CODEX_HOME')}}
# Preserve current user homes; saved build metadata must never replace them.
for key in ('HOME','CODEX_HOME'):
 if key in os.environ:env[key]=os.environ[key]
 else:env.pop(key,None)
env['WORKSPACE']=str(workspace);env['CONF_PATH']=str(workspace/'Conf')
env['PACKAGES_PATH']=':'.join(map(str,[workspace,base/'source',base/'source/MU_BASECORE',base/'source/Platforms']))
env['PATH']=':'.join(map(str,[base/'venv/bin',base/'toolchain/bin',base/'source/MU_BASECORE/BaseTools/BinWrappers/PosixLike',base/'source/MU_BASECORE/BaseTools/Source/C/bin']))+':/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin'
cmd=[str(base/'source/MU_BASECORE/BaseTools/BinWrappers/PosixLike/build'),'-p','G289Pkg/G289Wlan.dsc','-a','AARCH64','-b','DEBUG','-t','CLANGPDB','-n','4']
with (r/'dxe-build.log').open('w')as out:p=subprocess.run(cmd,cwd=workspace,env=env,stdout=out,stderr=out)
receipt={'command':cmd,'exit_code':p.returncode,'firmware_boot_image':False,'native_operations':0}
receipt['source_sha256']={str(p.relative_to(workspace)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((workspace/'G289Pkg').rglob('*')) if p.is_file()}
if not p.returncode:
 receipt['efi_sha256']=hashlib.sha256((workspace/'Build/G289Wlan/DEBUG_CLANGPDB/AARCH64/G289Pkg/Wlan/G289Wlan/OUTPUT/WlanBringupG622.efi').read_bytes()).hexdigest()
(r/'DXE-BUILD.json').write_text(json.dumps(receipt,indent=2)+'\n');print(p.returncode)
raise SystemExit(p.returncode)
