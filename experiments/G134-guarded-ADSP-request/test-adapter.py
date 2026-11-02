"""Compile the actual firmware adapter C with real UEFI headers and service models."""
from pathlib import Path
import argparse,subprocess,json,hashlib
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output.mkdir(exist_ok=False)
w=Path(__file__).resolve().parent;r=Path('/home/PROJECT_USER.guest/woa-open/mu_aloha_platforms')
configs=[(w.parent/'charging-G128/private/metadata-replay-02'/(n+'-config.bin')).read_bytes()for n in ['FULL_ADSP_DTB','FULL_ADSP']]
assert all(len(b)==568 for b in configs)
(a.output/'cfg-fixtures.h').write_text('static const unsigned char FixtureConfig[2][568]={'+','.join('{'+','.join(hex(v)for v in b)+'}'for b in configs)+'};\n')
incs=[w,a.output.resolve(),w/'private/candidate-source/Platforms/AndromedaPkg/Library/DeviceBootManagerLib',*[r/n for n in ['MU_BASECORE/MdePkg/Include','MU_BASECORE/MdePkg/Include/X64','MU_BASECORE/MdeModulePkg/Include','Platforms/AndromedaPkg/Include','MU_BASECORE/ArmPkg/Include']]]
cmd=['cc','-std=c11','-DNO_MSABI_VA_FUNCS','-fshort-wchar','-g','-O1','-fsanitize=address,undefined','-fno-omit-frame-pointer','-Werror=implicit-function-declaration','-Werror=incompatible-pointer-types','-Werror=int-conversion']+['-I'+str(n)for n in incs]+[str(w/n)for n in ['test-adapter.c','OpenPasObserver.c','OpenDspAdmission.c']]+['-o',str(a.output.resolve()/'test')]
x=subprocess.run(['colima','ssh','--']+cmd,capture_output=True,text=True);(a.output/'compiler.txt').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr
cases=['success','EL2','source-refused','inventory-refused','metadata-null','metadata-size','metadata-magic','metadata-status','metadata-flags','metadata-legacy','metadata-attempts','metadata-PAS-count','PIL-missing','SCM-missing','PIL-revision','PIL-method','SCM-revision','SCM-method','GOP-missing','GOP-many','GOP-overlap','GOP-second-overlap','GOP-overflow','EL0','EL3','CPU-read-fault','CPU-write-fault','CPU-alias','CPU-device','config-base','config-backup','config-postimage','hook-write-fail','restore-write-fail','stale-before-hook','slot-restore-changed','protocol-restore-changed','loader-no-PAS','DTB-post-fail','main-post-fail','transport-main-auth',*[f'service-{i}'for i in range(6)]]
code='''import subprocess,json
rows=[]
for case in %r:
 r=subprocess.run([%r,case,*([%r]if case=='success'else [])],capture_output=True,text=True)
 if r.returncode:print(json.dumps({'case':case,'code':r.returncode,'stdout':r.stdout,'stderr':r.stderr}));raise SystemExit(1)
 rows.append(json.loads(r.stdout))
print(json.dumps(rows))
'''%(cases,str(a.output.resolve()/'test'),str(a.output.resolve()/'modeled-OADP.bin'))
x=subprocess.run(['colima','ssh','--','python3','-c',code],capture_output=True,text=True);(a.output/'console.txt').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stdout+x.stderr
rows=json.loads(x.stdout)
result={'passed':True,'cases':len(rows),'actual_adapter_C':True,'ASan_UBSan':True,'native_operations':0,'config_SHA256':[hashlib.sha256(b).hexdigest()for b in configs],'source_SHA256':{n:hashlib.sha256((w/n).read_bytes()).hexdigest()for n in ['OpenGuardedAdsp.c','OpenGuardedAdsp.h','OpenPasObserver.c','OpenDspAdmission.c','test-adapter.c']},'models':['UEFI protocol and GOP inventory','source/metadata preflight result','stage-1 AT/PAR responses','original public PIL configuration method','secure-monitor results and callback failures','ACPI publication','TPL and console services'],'limits':['This is not a native firmware boot or secure authorization.','Underlying SMC/PIL latency, global DMA and stage-2 permissions remain unproved.'],'results':rows}
(a.output/'tests.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:result[k]for k in ['passed','cases','actual_adapter_C','ASan_UBSan','native_operations']}))
