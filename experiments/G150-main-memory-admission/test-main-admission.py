"""Exercise actual main admission C; UEFI/AT/MMIO remain explicit models.

Historical G116 provides clock/version/Demura values. An independent projection
of G147's pinned89 writes checks every modeled page translation, including both
sides of the large gap. No phone operation or target dereference is performed.
"""
from pathlib import Path
import argparse,hashlib,json,subprocess
w=Path(__file__).resolve().parent;p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--display',type=Path,default=w.parent/'display-G116/private/native-decoded.json')
p.add_argument('--replay',type=Path,default=w.parent/'charging-G147/private/main-target-replay-04.json')
p.add_argument('--output',required=True,type=Path)
a=p.parse_args();o=a.output.resolve();o.mkdir(parents=True,exist_ok=False)
sha=lambda b:hashlib.sha256(b).hexdigest()
j=json.loads(a.display.read_text());assert j['capture_code']==0 and j['complete_mask']==0x7fff
words={int(r['address'],16):int(r['first'],16) for region in j['regions'] for r in region['words'] if r['first']==r['second']}
assert words[0xae6a604]==words[0xae6b604]==0 and words[0xae00000]==0x90000001
raw=a.replay.read_bytes();assert sha(raw)=='c92416ad0eec6d8d87dd0d483238472bf5f8a53218911e590c72147e72145236'
j=json.loads(raw);assert j['passed'] and j['cases']==8 and len(j['complete_target_plan'])==89
pages=set()
for extent in j['complete_target_plan']:
 start,end=extent['address'],extent['address']+extent['bytes']
 assert 0x9ea00000<=start<end<=0xa3280000
 pages.update(range(start//4096,(end-1)//4096+1))
assert len(pages)==15851
header='static const UINT32 NativeClock[5]={'+','.join(hex(words[v]) for v in [0xaf08000,0xaf0800c,0xaf080a4,0xaf09000,0xaf09004])+'};\nstatic const UINT32 NativeVersion=0x90000001;\n'
header+='static const UINT64 ExpectedPages[15851]={'+','.join(hex(v*4096)+'ULL' for v in sorted(pages))+'};\n'
(o/'admission-fixtures.h').write_text(header)
r=Path('/home/PROJECT_USER.guest/woa-open/mu_aloha_platforms')
incs=[w,o,r/'MU_BASECORE/MdePkg/Include',r/'MU_BASECORE/MdePkg/Include/X64',r/'MU_BASECORE/MdeModulePkg/Include']
cmd=['cc','-std=c11','-D_POSIX_C_SOURCE=200112L','-DNO_MSABI_VA_FUNCS','-fshort-wchar','-g','-O1','-Wall','-Wextra','-Werror','-Wno-misleading-indentation','-Wno-parentheses','-fsanitize=address,undefined','-fno-omit-frame-pointer']+['-I'+str(x) for x in incs]+[str(w/'test-main-admission.c'),'-o',str(o/'test')]
r=subprocess.run(['colima','ssh','--']+cmd,capture_output=True,text=True);(o/'compiler.txt').write_text(r.stdout+r.stderr);assert not r.returncode,r.stderr
cases=['success', 'EL2', 'device-nGnRE', 'device-UC-RO-XP', 'no-footprint', 'noncanonical-footprint', 'gcd-error', 'gcd-warning', 'gcd-base', 'gcd-size', 'gcd-type', 'gcd-attributes', 'gcd-capability', 'gcd-image-owner', 'gcd-device-owner', 'map-first-error', 'map-first-warning', 'map-first-zero', 'map-first-large', 'map-first-stride-small', 'map-first-stride-large', 'map-first-stride-unaligned', 'pool-fail', 'map-second-error', 'map-second-warning', 'map-second-zero', 'map-second-large', 'map-second-stride-zero', 'map-second-stride-small', 'map-second-stride-large', 'map-second-stride-unaligned', 'map-size-unaligned', 'map-version', 'map-missing', 'map-type', 'map-attribute', 'map-base', 'map-pages', 'map-overflow', 'map-page-overflow', 'map-duplicate', 'bad-EL', 'CPU-read-fault', 'CPU-write-fault', 'CPU-last-page-fault', 'CPU-read-alias', 'CPU-write-alias', 'CPU-WB', 'CPU-last-page-WB', 'device-gcd-error', 'device-gcd-warning', 'device-gcd-type', 'device-gcd-short', 'device-gcd-base', 'device-gcd-overflow', 'device-gcd-capability', 'device-gcd-WB', 'device-gcd-mixed', 'device-gcd-RP', 'device-AT-fault', 'device-AT-alias', 'device-AT-NC', 'device-AT-GRE', 'clock-reset', 'clock-MDP-off', 'clock-MDP-unrequested', 'clock-AHB-off', 'clock-AHB-unrequested', 'clock-core-off', 'clock-hw-trigger', 'clock-sw-override', 'clock-collapse', 'clock-down-complete', 'clock-up-incomplete', 'gate-loss-before-demura', 'gate-loss-after-demura', 'display-version', 'demura0', 'demura1', 'demura-unknown-bits', 'before-copy', 'duplicate-copy', 'null-log', 'forbidden-c7b7000', 'forbidden-c7b7008', 'forbidden-b000000', 'read-budget', 'map-tail-owner', 'map-gap-owner', 'map-irrelevant', 'CPU-before-gap-fault', 'CPU-after-gap-fault', 'CPU-last-write-fault', 'reenter-GCD', 'reenter-map', 'reenter-AT', 'reenter-MMIO', 'reenter-log', 'pre-no-footprint', 'pre-noncanonical-footprint', 'pre-gcd-image-owner', 'pre-map-tail-owner', 'pre-map-gap-owner', 'pre-CPU-last-page-fault', 'pre-CPU-after-gap-fault', 'pre-CPU-last-page-WB', 'pre-clock-core-off', 'pre-gate-loss-after-demura', 'pre-demura1', 'pre-reenter-log', 'post-no-footprint', 'post-noncanonical-footprint', 'post-gcd-image-owner', 'post-map-tail-owner', 'post-map-gap-owner', 'post-CPU-last-page-fault', 'post-CPU-after-gap-fault', 'post-CPU-last-page-WB', 'post-clock-core-off', 'post-gate-loss-after-demura', 'post-demura1', 'post-reenter-log']
script='''import subprocess,json
rows=[]
for case in %r:
 r=subprocess.run([%r,case],capture_output=True,text=True)
 if r.returncode or r.stderr:print(json.dumps({'case':case,'exit':r.returncode,'stdout':r.stdout,'stderr':r.stderr}));raise SystemExit(1)
 rows.append(json.loads(r.stdout))
print(json.dumps(rows))
'''%(cases,str(o/'test'))
r=subprocess.run(['colima','ssh','--','python3','-c',script],capture_output=True,text=True);(o/'console.txt').write_text(r.stdout+r.stderr);assert not r.returncode,r.stdout+r.stderr
rows=json.loads(r.stdout);assert len(rows)==len(cases)
report={'passed':True,'cases':len(rows),'actual_firmware_C':True,'ASan_UBSan':True,'native_phone_operations':0,
 'source_sha256':{n:sha((w/n).read_bytes()) for n in ['OpenMainAdmission.c','OpenMainAdmission.h','OpenMainAdmissionPlan.h','generate-main-pages.py','test-main-admission.c','test-main-admission.py','OpenDspAdmission.h','OpenPasObserver.h']},
 'fixture_sha256':{'historical_G116_display':sha(a.display.read_bytes()),'original_loader_G147_replay':sha(raw)},
 'CPU_pages_per_check':15851,'AT_queries_per_successful_check':31707,'MMIO_reads_per_successful_check':43,
 'models':['UEFI GCD/memory-map/allocation services','AT outputs, checked against independent original-loader page coverage','eight fixed read-only MMIO values/transitions from historical G116'],
 'limits':['Actual C and fixed page-plan verification only; no native main memory access, original main MEM_SETUP/AUTH, DSP start, GLINK or charging qualification.','Finite observations do not establish global DMA/stage2 ownership or acquire a production power lease.','Not integrated into firmware or the original loader adapter.'],
 'results':rows}
(o/'tests.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items() if k!='results'},indent=2))
