"""Compile/run actual adapter and recorder with real UEFI headers in Colima."""
from pathlib import Path
import argparse,hashlib,json,subprocess
p=argparse.ArgumentParser();p.add_argument('--replay',type=Path,default=Path(__file__).resolve().parent.parent/'charging-G147/private/main-target-replay-04.json');p.add_argument('--layout',type=Path,default=Path(__file__).resolve().parent.parent/'charging-G147/private/main-layout-summary.json');p.add_argument('--payload-dir',type=Path,default=Path(__file__).resolve().parent.parent/'charging-G118/private/firmware-input/firmware/image');p.add_argument('--output',type=Path,required=True);a=p.parse_args();o=a.output.resolve();assert not o.exists();o.mkdir(parents=True);w=Path(__file__).resolve().parent;r=Path('/home/PROJECT_USER.guest/woa-open/mu_aloha_platforms')
cfg=[(w.parent/'charging-G128/private/metadata-replay-02'/(n+'-config.bin')).read_bytes()for n in ['FULL_ADSP_DTB','FULL_ADSP']];assert all(len(x)==568 for x in cfg)
(o/'cfg-fixtures.h').write_text('static const unsigned char FixtureConfig[2][568]={'+','.join('{'+','.join(hex(v)for v in b)+'}'for b in cfg)+'};\n')
sha=lambda b:hashlib.sha256(b).hexdigest()
raw=a.replay.read_bytes();assert sha(raw)=='c92416ad0eec6d8d87dd0d483238472bf5f8a53218911e590c72147e72145236'
j=json.loads(raw);assert j['passed']and j['cases']==8
for name,h in j['payload_inputs_sha256'].items():assert sha((a.payload_dir/name).read_bytes())==h,name
plan=j['complete_target_plan'];layout=json.loads(a.layout.read_text());assert layout['source_report_sha256']==sha(raw)and layout['write_overlaps_bytes']==0
files=[json.dumps(row['name'])if row['kind']=='file-copy-model'else'NULL'for row in plan]
holes=','.join('{'+str(int(row['base'],16))+'ULL,'+str(int(row['end_exclusive'],16))+'ULL}'for row in layout['untouched_ranges'])
expected_reads=sum((row['bytes']+4095)//4096 for row in plan)
bases=','.join(str(row['address'])+'ULL'for row in plan);sizes=','.join(str(row['bytes'])+'ULL'for row in plan);kinds=','.join('1'if row['kind']=='file-copy-model'else'2'for row in plan)
(o/'model-fixtures.h').write_text('static const char*FileName[89]={'+','.join(files)+'};\nstatic const unsigned long long ModelBase[89]={'+bases+'},ModelBytes[89]={'+sizes+'};\nstatic const unsigned ModelKind[89]={'+kinds+'};\nstatic const unsigned long long Untouched[5][2]={'+holes+'};\nstatic const unsigned ExpectedReads='+str(expected_reads)+';\n')
lib=w/'private/candidate-source/Platforms/AndromedaPkg/Library/DeviceBootManagerLib'
incs=[w,o,lib,*[r/n for n in ['MU_BASECORE/MdePkg/Include','MU_BASECORE/MdePkg/Include/X64','MU_BASECORE/MdeModulePkg/Include','Platforms/AndromedaPkg/Include','MU_BASECORE/ArmPkg/Include']]]
sources=[w/'test-adapter.c',w/'OpenPasObserver.c',w/'OpenScmErrorCapture.c',w/'OpenDspAdmission.c',w/'OpenMainAdmission.c',w/'OpenMainPayload.c']
cmd=['cc','-std=c11','-DNO_MSABI_VA_FUNCS','-D_GNU_SOURCE','-DOPEN_MAIN_ADMISSION_MODEL','-fshort-wchar','-g','-O1','-fsanitize=address,undefined','-fno-omit-frame-pointer','-Werror=implicit-function-declaration','-Werror=incompatible-pointer-types','-Werror=int-conversion']+['-I'+str(n)for n in incs]+[str(n)for n in sources]+['-o',str(o/'test')]
q=subprocess.run(['colima','ssh','--']+cmd,capture_output=True,text=True);(o/'compiler.txt').write_text(q.stdout+q.stderr);assert q.returncode==0,q.stderr
cases=['PIL-footprint-refused','CPU-PIL-WB','CPU-SCM-NC','error-native-code','admission-init-refused','copy-admission-refused','payload-admission-refused','error-auth','service-auth','header-auth','loader-segment-failure','loader-PRE-failure','loader-POST-failure','success','EL2','cached-serial','source-refused','inventory-refused','metadata-null','metadata-size','metadata-magic','metadata-status','metadata-flags','metadata-legacy','metadata-attempts','metadata-PAS-count','PIL-missing','SCM-missing','PIL-revision','PIL-method','SCM-revision','SCM-method','GOP-missing','GOP-many','GOP-overlap','GOP-second-overlap','GOP-overflow','EL0','EL3','CPU-read-fault','CPU-write-fault','CPU-alias','CPU-device','config-base','config-backup','config-postimage','hook-write-fail','restore-write-fail','serial-hook-write-fail','serial-restore-write-fail','stale-before-hook','serial-stale-before-hook','protocol-restore-changed','already-proxy','loader-no-PAS','error-init','error-mem','error-unsupported','error-already','service-init','service-mem','header-init','header-mem','serial-change-after-init','serial-change-after-mem','slot-change-after-mem','bad-log','nonstack-log','oversized-log','other-serial','DSP-publication-fail','serial-publication-fail']
cases+=['main-error-init','main-error-mem','main-error-auth','main-service-init','main-service-mem','main-service-auth','main-header-init','main-header-mem','main-header-auth','main-loader-no-PAS','main-loader-PRE-failure','main-loader-segment-failure','main-loader-POST-failure','owner-before-marker','main-copy-owner','main-pre-AT','main-post-AT','main-pre-demura','main-post-demura','main-hash-last','main-zero-last','main-read-error','main-owner-after-read','main-changed-holes']
script='''import json,os,subprocess
env=dict(os.environ,ASAN_OPTIONS='detect_stack_use_after_return=0')
rows=[]
for case in %r:
 q=subprocess.run([%r,case,%r+'/'+case,%r],env=env,capture_output=True,text=True)
 if q.returncode:print(json.dumps({'case':case,'code':q.returncode,'stdout':q.stdout,'stderr':q.stderr}));raise SystemExit(1)
 rows.append(json.loads(q.stdout))
print(json.dumps(rows))
'''%(cases,str(o/'test'),str(o/'wire'),str(a.payload_dir.resolve()))
(o/'wire').mkdir()
q=subprocess.run(['colima','ssh','--','python3','-c',script],capture_output=True,text=True);(o/'console.txt').write_text(q.stdout+q.stderr);assert q.returncode==0,q.stdout+q.stderr
out={'passed':True,'cases':len(cases),'actual_adapter_policy_main_admission_verifier_parser_C':True,'real_main_SHA':True,'real_UEFI_headers':True,'ASan_UBSan':True,'ASan_fake_stack_disabled':'Only use-after-return fake-stack mode is disabled so live frames retain their native relative layout.','native_operations':0,'source_sha256':{n:hashlib.sha256((w/n).read_bytes()).hexdigest()for n in ['OpenGuardedAdsp.c','OpenGuardedAdsp.h','OpenPasObserver.c','OpenPasObserver.h','OpenScmErrorCapture.c','OpenScmErrorCapture.h','OpenMainAdmission.c','OpenMainAdmission.h','OpenMainAdmissionPlan.h','OpenMainPayload.c','OpenMainPayload.h','OpenMainPayloadPlan.h','OpenSha256.h','test-adapter.c','test-adapter.py']},'results':json.loads(q.stdout),'limits':['UEFI protocols/GCD/maps/GOP, CPU AT/PAR, fixed MMIO, original PIL, DTB admission and secure API responses are models. Main physical reads use captured-file model RAM; actual main admission/verifier/SHA are linked.','Actual firmware/native secure behavior is not established.']}
(o/'tests.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({k:v for k,v in out.items()if k not in ['results','source_sha256']},indent=2))
