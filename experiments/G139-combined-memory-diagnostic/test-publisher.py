from pathlib import Path
import argparse,hashlib,json,subprocess
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args()
w=Path(__file__).resolve().parent;a.output.mkdir(exist_ok=False)
root='/home/PROJECT_USER.guest/woa-open/mu_aloha_platforms'
incs=[str(w),*[root+'/'+s for s in ['MU_BASECORE/MdePkg/Include','MU_BASECORE/MdePkg/Include/X64','MU_BASECORE/MdeModulePkg/Include']]]
exe=a.output.resolve()/'test'
cmd=['cc','-std=c11','-DNO_MSABI_VA_FUNCS','-fshort-wchar','-g','-O1','-fsanitize=address,undefined','-fno-omit-frame-pointer','-Werror=implicit-function-declaration','-Werror=incompatible-pointer-types','-Werror=int-conversion']+['-I'+s for s in incs]+[str(w/'test-publisher.c'),'-o',str(exe)]
r=subprocess.run(['colima','ssh','--']+cmd,capture_output=True,text=True);(a.output/'compiler.txt').write_text(r.stdout+r.stderr);assert r.returncode==0,r.stderr
cases=['success','text-pool-fail','cpu-pool-fail','header-pool-fail','acpi-error','acpi-warning','acpi-null','install-error','install-warning','bad-el','text-clipped','cpu-fault','cpu-alias','cpu-mixed-tags']
code='''import json,subprocess
rows=[]
for case in %r:
 r=subprocess.run([%r,case],cwd=%r,capture_output=True,text=True)
 if r.returncode:print(json.dumps({'case':case,'exit':r.returncode,'stdout':r.stdout,'stderr':r.stderr}));raise SystemExit(1)
 rows.append(json.loads(r.stdout))
print(json.dumps(rows))
'''%(cases,str(exe),str(a.output.resolve()))
r=subprocess.run(['colima','ssh','--','python3','-c',code],capture_output=True,text=True);(a.output/'console.txt').write_text(r.stdout+r.stderr);assert r.returncode==0,r.stdout+r.stderr
report={'passed':True,'cases':len(cases),'ASan_UBSan':True,'native_phone_operations':0,'actual_publication_C':True,'source_sha256':{n:hashlib.sha256((w/n).read_bytes()).hexdigest() for n in ['OpenPilInventory.c','OpenPilCpuInventory.c','OpenPilCpuInventory.h','test-publisher.c']},'results':json.loads(r.stdout),'models':['ACPI/heap services and host PrintLib formatting','Fixed AT callback; no native address-translation instructions','Memory-map collector modeled separately in the footprint suite']}
(a.output/'tests.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:report[k] for k in ['passed','cases','ASan_UBSan','native_phone_operations']}))
