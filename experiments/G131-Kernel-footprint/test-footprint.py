"""Actual UEFI collector C under ASan/UBSan, with explicit service boundaries."""
from pathlib import Path
import argparse, hashlib, json, subprocess
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',required=True,type=Path);a=p.parse_args()
a.output.mkdir(exist_ok=False);w=Path(__file__).resolve().parent
root='/home/PROJECT_USER.guest/woa-open/mu_aloha_platforms'
incs=[str(w),*[root+'/'+s for s in ['MU_BASECORE/MdePkg/Include','MU_BASECORE/MdePkg/Include/X64','MU_BASECORE/MdeModulePkg/Include','Platforms/AndromedaPkg/Include','MU_BASECORE/ArmPkg/Include']]]
exe=a.output.resolve()/'test'
cmd=['cc','-std=c11','-D_POSIX_C_SOURCE=200112L','-DNO_MSABI_VA_FUNCS','-fshort-wchar','-g','-O1','-fsanitize=address,undefined','-fno-omit-frame-pointer','-Werror=implicit-function-declaration','-Werror=incompatible-pointer-types','-Werror=int-conversion']+['-I'+s for s in incs]+[str(w/'test-footprint.c'),'-o',str(exe)]
r=subprocess.run(['colima','ssh','--']+cmd,capture_output=True,text=True);(a.output/'compiler.txt').write_text(r.stdout+r.stderr);assert r.returncode==0,r.stderr
cases=['success','platform-null','platform-missing','gcd-error','gcd-null','gcd-count','gcd-many','gcd-overflow','pool-fail','efi-error','efi-zero-stride','efi-short-stride','efi-large-stride','efi-bad-size','efi-too-large','efi-version','efi-overflow','efi-many','efi-unreserved','hob-null','hob-first-type','hob-bad-length','hob-short-alloc','hob-no-end','hob-end-mismatch','hob-too-far','hob-overflow','hob-fv-overflow','images-error','images-null','images-count','image-error','image-null','image-overflow','image-overlap','images-many-overlap','config-count','config-null','config-overlap','config-many','duplicate']
code='''import subprocess,json
rows=[]
for case in %r:
 r=subprocess.run([%r,case],capture_output=True,text=True)
 if r.returncode: print(json.dumps({'case':case,'exit':r.returncode,'stdout':r.stdout,'stderr':r.stderr}));raise SystemExit(1)
 rows.append(json.loads(r.stdout))
print(json.dumps(rows))
'''%(cases,str(exe))
r=subprocess.run(['colima','ssh','--','python3','-c',code],capture_output=True,text=True);(a.output/'console.txt').write_text(r.stdout+r.stderr);assert r.returncode==0,r.stdout+r.stderr
rows=json.loads(r.stdout);assert len(rows)==len(cases)
report={'passed':True,'cases':len(rows),'actual_collector_C':True,'ASan_UBSan':True,'native_phone_operations':0,'models':['UEFI boot/DXE memory and image services','platform descriptors and bounded HOB lists','host report formatting (EFI GUID rendered as pointer)'],'limits':['Queries complete describes collection, not memory eligibility or global ownership.','No native memory reservation, device/DMA access, firmware boot or PAS operation occurs.'],'source_sha256':{n:hashlib.sha256((w/n).read_bytes()).hexdigest()for n in ['OpenKernelFootprint.c','OpenKernelFootprint.h','test-footprint.c']},'results':rows}
(a.output/'tests.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:report[k]for k in ['passed','cases','actual_collector_C','ASan_UBSan','native_phone_operations']}))
