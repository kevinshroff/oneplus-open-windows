"""Compile actual diagnostic C with firmware headers, then run bounded models."""
import argparse,hashlib,json,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--bindings',type=Path,required=True);p.add_argument('--records',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
a=p.parse_args();a.output.mkdir(exist_ok=False);w=Path(__file__).resolve().parent;root=Path('/home/PROJECT_USER.guest/woa-open/mu_aloha_platforms')
incs=[w,a.bindings.resolve(),root/'Platforms/AndromedaPkg/Library/DeviceBootManagerLib',root/'MU_BASECORE/MdePkg/Include',root/'MU_BASECORE/MdePkg/Include/X64']
exe=a.output.resolve()/'test'
cmd=['cc','-std=c11','-D_POSIX_C_SOURCE=200112L','-DNO_MSABI_VA_FUNCS','-fshort-wchar','-g','-O1','-fsanitize=address,undefined','-fno-omit-frame-pointer','-Werror=implicit-function-declaration','-Werror=incompatible-pointer-types','-Werror=int-conversion']+['-I'+str(x)for x in incs]+[str(w/'test-native-probe.c'),'-o',str(exe)]
x=subprocess.run(['colima','ssh','--']+cmd,capture_output=True,text=True);(a.output/'compiler.txt').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stdout+x.stderr
cases=['success','legacy','no-PIL','no-SCM','PIL-code','SCM-code','PIL-revision','PIL-getter','SCM-function','image-size','image-enumeration','duplicate-image','too-many-images','config-warning','config-data','hash-allocation','preflight-failed','metadata-error','metadata-partial','cached-hash','uncached-hash','header-error','uncached-release','uncached-short-release','pool-free','no-attributes','attribute-error','read-only-slot','no-ACPI','install-error','report-allocation']
code='''import subprocess,json
exe=%r
cases=%r
args=%r
rows=[]
for case in cases:
 p=subprocess.run([exe,case,*args],capture_output=True,text=True)
 if p.returncode:print(json.dumps({'case':case,'returncode':p.returncode,'stdout':p.stdout,'stderr':p.stderr}));raise SystemExit(1)
 rows.append(json.loads(p.stdout))
print(json.dumps(rows))
'''%(str(exe),cases,[str(a.bindings.resolve()),str(a.records.resolve()),str(w.parent/'charging-G118/private/firmware-input/firmware/image'),str(a.output.resolve()/'modeled-OPAS.bin')])
x=subprocess.run(['colima','ssh','--','python3','-c',code],capture_output=True,text=True);(a.output/'console.txt').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stdout+x.stderr
rows=json.loads(x.stdout);assert len(rows)==31 and all(r['passed']for r in rows)
r={'passed':True,'cases':len(rows),'ASan_UBSan':True,'actual_C_source':True,'boundaries':'UEFI protocols/images, actual mapped PE bytes plus original-config/MDT fixtures; ARM64 helper calls modeled. Not a native firmware boot.','native_phone_operations':0,'source_sha256':{n:hashlib.sha256((w/n).read_bytes()).hexdigest()for n in ['OpenPilMetadataProbe.c','OpenPilMetadataProbe.h','test-native-probe.c']},'results':rows}
(a.output/'tests.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({k:v for k,v in r.items()if k!='results'},indent=2))
