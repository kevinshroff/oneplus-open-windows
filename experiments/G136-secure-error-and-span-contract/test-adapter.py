"""Compile/run actual adapter and recorder with real UEFI headers in Colima."""
from pathlib import Path
import argparse,hashlib,json,subprocess
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();o=a.output.resolve();assert not o.exists();o.mkdir(parents=True);w=Path(__file__).resolve().parent;r=Path('/home/PROJECT_USER.guest/woa-open/mu_aloha_platforms')
cfg=[(w.parent/'charging-G128/private/metadata-replay-02'/(n+'-config.bin')).read_bytes()for n in ['FULL_ADSP_DTB','FULL_ADSP']];assert all(len(x)==568 for x in cfg)
(o/'cfg-fixtures.h').write_text('static const unsigned char FixtureConfig[2][568]={'+','.join('{'+','.join(hex(v)for v in b)+'}'for b in cfg)+'};\n')
lib=w/'private/candidate-source/Platforms/AndromedaPkg/Library/DeviceBootManagerLib'
incs=[w,o,lib,*[r/n for n in ['MU_BASECORE/MdePkg/Include','MU_BASECORE/MdePkg/Include/X64','MU_BASECORE/MdeModulePkg/Include','Platforms/AndromedaPkg/Include','MU_BASECORE/ArmPkg/Include']]]
sources=[w/'test-adapter.c',w/'OpenPasObserver.c',w/'OpenScmErrorCapture.c',lib/'OpenDspAdmission.c']
cmd=['cc','-std=c11','-DNO_MSABI_VA_FUNCS','-fshort-wchar','-g','-O1','-fsanitize=address,undefined','-fno-omit-frame-pointer','-Werror=implicit-function-declaration','-Werror=incompatible-pointer-types','-Werror=int-conversion']+['-I'+str(n)for n in incs]+[str(n)for n in sources]+['-o',str(o/'test')]
q=subprocess.run(['colima','ssh','--']+cmd,capture_output=True,text=True);(o/'compiler.txt').write_text(q.stdout+q.stderr);assert q.returncode==0,q.stderr
cases=['success','EL2','cached-serial','source-refused','inventory-refused','metadata-null','metadata-size','metadata-magic','metadata-status','metadata-flags','metadata-legacy','metadata-attempts','metadata-PAS-count','PIL-missing','SCM-missing','PIL-revision','PIL-method','SCM-revision','SCM-method','GOP-missing','GOP-many','GOP-overlap','GOP-second-overlap','GOP-overflow','EL0','EL3','CPU-read-fault','CPU-write-fault','CPU-alias','CPU-device','config-base','config-backup','config-postimage','hook-write-fail','restore-write-fail','serial-hook-write-fail','serial-restore-write-fail','stale-before-hook','serial-stale-before-hook','protocol-restore-changed','already-proxy','loader-no-PAS','error-init','error-mem','error-unsupported','error-already','service-init','service-mem','header-init','header-mem','serial-change-after-init','serial-change-after-mem','slot-change-after-mem','bad-log','nonstack-log','oversized-log','other-serial','DSP-publication-fail','serial-publication-fail']
script='''import json,os,subprocess
env=dict(os.environ,ASAN_OPTIONS='detect_stack_use_after_return=0')
rows=[]
for case in %r:
 q=subprocess.run([%r,case,*([%r]if case=='error-mem'else[])],env=env,capture_output=True,text=True)
 if q.returncode:print(json.dumps({'case':case,'code':q.returncode,'stdout':q.stdout,'stderr':q.stderr}));raise SystemExit(1)
 rows.append(json.loads(q.stdout))
print(json.dumps(rows))
'''%(cases,str(o/'test'),str(o/'modeled'))
q=subprocess.run(['colima','ssh','--','python3','-c',script],capture_output=True,text=True);(o/'console.txt').write_text(q.stdout+q.stderr);assert q.returncode==0,q.stdout+q.stderr
out={'passed':True,'cases':len(cases),'actual_adapter_and_parser_C':True,'real_UEFI_headers':True,'ASan_UBSan':True,'ASan_fake_stack_disabled':'Only use-after-return fake-stack mode is disabled so live frames retain their native relative layout.','native_operations':0,'source_sha256':{n:hashlib.sha256((w/n).read_bytes()).hexdigest()for n in ['OpenGuardedAdsp.c','OpenGuardedAdsp.h','OpenPasObserver.c','OpenPasObserver.h','OpenScmErrorCapture.c','OpenScmErrorCapture.h','test-adapter.c']},'results':json.loads(q.stdout),'limits':['UEFI protocols, GOP, CPU AT/PAR, original PIL and secure API responses are models.','Actual firmware/native secure behavior is not established.']}
(o/'tests.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({k:v for k,v in out.items()if k not in ['results','source_sha256']},indent=2))
