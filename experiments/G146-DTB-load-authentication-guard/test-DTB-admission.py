"""Run actual firmware C against service faults and historical native fixtures.

AT, MMIO and SHA/target dereference are explicit boundaries. Digest fixtures
come from hashlib over the exact saved CFGL payload and one corrupted byte.
"""
from pathlib import Path
import argparse,hashlib,json,subprocess
w=Path(__file__).resolve().parent
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--display',type=Path,default=w.parent/'display-G116/private/native-decoded.json')
p.add_argument('--payload',type=Path,default=w.parent/'charging-G118/private/firmware-input/firmware/image/adsp_dtb.b01')
p.add_argument('--output',required=True,type=Path)
a=p.parse_args();o=a.output.resolve();o.mkdir(parents=True,exist_ok=False)
j=json.loads(a.display.read_text());assert j['capture_code']==0 and j['complete_mask']==0x7fff
words={int(r['address'],16):int(r['first'],16)for region in j['regions']for r in region['words']if r['first']==r['second']}
assert words[0xae6a604]==words[0xae6b604]==0 and words[0xae00000]==0x90000001
data=a.payload.read_bytes();assert len(data)==8376 and hashlib.sha256(data).hexdigest()=='f71892ad4ff2ac1100a07f63b4a5ef246749a95937a797d50480e7c70b1b2f94'
mutated=bytearray(data);mutated[17]^=1
header='static const UINT32 NativeClock[5]={'+','.join(hex(words[v])for v in [0xaf08000,0xaf0800c,0xaf080a4,0xaf09000,0xaf09004])+'};\n'
header+='static const UINT32 NativeVersion=0x90000001;\n'
for name,value in [('ActualPayloadDigest',hashlib.sha256(data).digest()),('MutatedPayloadDigest',hashlib.sha256(mutated).digest())]:
 header+='static const UINT8 '+name+'[32]={'+','.join(hex(v)for v in value)+'};\n'
(o/'admission-fixtures.h').write_text(header)
root='/home/PROJECT_USER.guest/woa-open/mu_aloha_platforms'
incs=[w,o,*[Path(root)/s for s in ['MU_BASECORE/MdePkg/Include','MU_BASECORE/MdePkg/Include/X64','MU_BASECORE/MdeModulePkg/Include','MU_BASECORE/CryptoPkg/Include']]]
cmd=['cc','-std=c11','-D_POSIX_C_SOURCE=200112L','-DNO_MSABI_VA_FUNCS','-fshort-wchar','-O1','-g','-fsanitize=address,undefined','-fno-omit-frame-pointer',
 '-Werror=implicit-function-declaration','-Werror=incompatible-pointer-types','-Werror=int-conversion']+['-I'+str(v)for v in incs]+[str(w/'test-DTB-admission.c'),'-o',str(o/'test')]
r=subprocess.run(['colima','ssh','--']+cmd,capture_output=True,text=True);(o/'compiler.txt').write_text(r.stdout+r.stderr);assert r.returncode==0,r.stderr
cases=['success','EL2','device-nGnRE','device-UC-RO-XP','no-footprint','noncanonical-footprint','gcd-error','gcd-warning','gcd-base','gcd-size','gcd-type','gcd-attributes','gcd-capability','gcd-image-owner','gcd-device-owner',
 'map-first-error','map-first-warning','map-first-zero','map-first-large','map-first-stride-small','map-first-stride-large','map-first-stride-unaligned','pool-fail',
 'map-second-error','map-second-warning','map-second-zero','map-second-large','map-second-stride-zero','map-second-stride-small','map-second-stride-large','map-second-stride-unaligned','map-size-unaligned','map-version','map-missing','map-type','map-attribute','map-base','map-pages','map-overflow','map-page-overflow','map-duplicate',
 'bad-EL','CPU-read-fault','CPU-write-fault','CPU-last-page-fault','CPU-read-alias','CPU-write-alias','CPU-WB','CPU-last-page-WB',
 'device-gcd-error','device-gcd-warning','device-gcd-type','device-gcd-short','device-gcd-base','device-gcd-overflow','device-gcd-capability','device-gcd-WB','device-gcd-mixed','device-gcd-RP','device-AT-fault','device-AT-alias','device-AT-NC','device-AT-GRE',
 'clock-reset','clock-MDP-off','clock-MDP-unrequested','clock-AHB-off','clock-AHB-unrequested','clock-core-off','clock-hw-trigger','clock-sw-override','clock-collapse','clock-down-complete','clock-up-incomplete','gate-loss-before-demura','gate-loss-after-demura','display-version','demura0','demura1','demura-unknown-bits',
 'before-copy','duplicate-copy','null-log','forbidden-c7b7000','forbidden-c7b7008','forbidden-b000000','read-budget','hash-service-fail','hash-mismatch',
 'payload-gcd-image-owner','payload-CPU-last-page-WB','payload-clock-core-off','payload-demura1','posthash-gcd-image-owner','posthash-CPU-last-page-fault','posthash-gate-loss-before-demura','posthash-demura0']
script='''import subprocess,json
rows=[]
for case in %r:
 r=subprocess.run([%r,case],capture_output=True,text=True)
 if r.returncode or r.stderr:print(json.dumps({'case':case,'exit':r.returncode,'stdout':r.stdout,'stderr':r.stderr}));raise SystemExit(1)
 rows.append(json.loads(r.stdout))
print(json.dumps(rows))
'''%(cases,str(o/'test'))
r=subprocess.run(['colima','ssh','--','python3','-c',script],capture_output=True,text=True);(o/'console.txt').write_text(r.stdout+r.stderr)
assert r.returncode==0,r.stdout+r.stderr
rows=json.loads(r.stdout);assert len(rows)==len(cases)
report={'passed':True,'cases':len(rows),'actual_firmware_C':True,'ASan_UBSan':True,'native_phone_operations':0,
 'source_sha256':{n:hashlib.sha256((w/n).read_bytes()).hexdigest()for n in ['OpenDtbAdmission.c','OpenDtbAdmission.h','test-DTB-admission.c','test-DTB-admission.py']},
 'fixture_sha256':{'historical_G116_display':hashlib.sha256(a.display.read_bytes()).hexdigest(),'payload':hashlib.sha256(data).hexdigest()},
 'models':['UEFI memory maps/allocation and GCD','AT results','fixed read-only MMIO values and transitions','SHA service and target address dereference; actual saved payload/hashlib digest fixtures'],
 'limits':['No native mapping, hardware ownership, DTB data access, AUTH or firmware build is qualified.','Finite Demura/source-map checks do not exclude every unobserved DMA master or acquire a power lease.'],
 'results':rows}
(o/'tests.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({k:v for k,v in report.items()if k!='results'},indent=2))
