"""Link actual admission, PAS policy and verifier/SHA against captured-file model RAM."""
from pathlib import Path
import argparse,hashlib,json,subprocess
w=Path(__file__).resolve().parent;p=argparse.ArgumentParser()
p.add_argument('--sequence-root',type=Path,default=w.parent/'charging-G149')
p.add_argument('--display',type=Path,default=w.parent/'display-G116/private/native-decoded.json')
p.add_argument('--verifier-root',type=Path,default=w.parent/'charging-G148')
p.add_argument('--native',type=Path,default=w.parent/'charging-G144/private/native-analysis.json')
p.add_argument('--replay',type=Path,default=w.parent/'charging-G147/private/main-target-replay-04.json')
p.add_argument('--layout',type=Path,default=w.parent/'charging-G147/private/main-layout-summary.json')
p.add_argument('--payload-dir',type=Path,default=w.parent/'charging-G118/private/firmware-input/firmware/image')
p.add_argument('--output',type=Path,required=True);a=p.parse_args();verifier=a.verifier_root.resolve();o=a.output.resolve();o.mkdir(parents=True,exist_ok=False)
sha=lambda b:hashlib.sha256(b).hexdigest()
sequence=a.sequence_root.resolve()
for name,h in {'OpenPasObserver.c':'f095486486c8c3eeab7ea3e1180df14bfd7b4a8553503178ce8429410698c64e','OpenPasObserver.h':'99b15a34942ff3f04258e01a808348f4832b4c1c45ef96f38d8657b058b752f8'}.items():assert sha((sequence/name).read_bytes())==h
for name,h in {'OpenMainPayload.c':'ba1ec95572fb42f0be9786542e1b019e679bcc4465dfac0d9d71f036e4c251a9','OpenMainPayload.h':'f44874e7eaf976d8143badeeae5a831f5de68caed1cddae8bcedb4bc44c672f5','OpenMainPayloadPlan.h':'31a4796f99b803881e3705a009132dcbedd370b20ca971b5c964ff82135a1941'}.items():assert sha((verifier/name).read_bytes())==h

assert sha(a.replay.read_bytes())=='c92416ad0eec6d8d87dd0d483238472bf5f8a53218911e590c72147e72145236'
j=json.loads(a.replay.read_text());assert j['passed']and j['cases']==8
assert sha((verifier/'OpenSha256.h').read_bytes())=='33b1ac0bab27454237686000ee66f8c9604c68fbaa90bc06545ca089e2dac227'
for name,h in j['payload_inputs_sha256'].items():assert sha((a.payload_dir/name).read_bytes())==h,name
plan=j['complete_target_plan']
display=json.loads(a.display.read_text());assert display['capture_code']==0 and display['complete_mask']==0x7fff
words={int(r['address'],16):int(r['first'],16) for region in display['regions'] for r in region['words'] if r['first']==r['second']}
assert words[0xae6a604]==words[0xae6b604]==0 and words[0xae00000]==0x90000001
pages=set()
for row in plan:pages.update(range(row['address']//4096,(row['address']+row['bytes']-1)//4096+1))
assert len(pages)==15851
(o/'admission-fixtures.h').write_text('static const UINT32 NativeClock[5]={'+','.join(hex(words[v]) for v in [0xaf08000,0xaf0800c,0xaf080a4,0xaf09000,0xaf09004])+'};\nstatic const UINT32 NativeVersion=0x90000001;\nstatic const UINT64 ExpectedPages[15851]={'+','.join(hex(v*4096)+'ULL' for v in sorted(pages))+'};\n')
layout=json.loads(a.layout.read_text());assert layout['source_report_sha256']==sha(a.replay.read_bytes())and layout['write_overlaps_bytes']==0
files=[json.dumps(r['name'])if r['kind']=='file-copy-model'else'NULL'for r in plan]
holes=','.join('{'+str(int(r['base'],16))+'ULL,'+str(int(r['end_exclusive'],16))+'ULL}'for r in layout['untouched_ranges'])
expected_reads=sum((r['bytes']+4095)//4096 for r in plan)
bases=','.join(str(r['address'])+'ULL'for r in plan);sizes=','.join(str(r['bytes'])+'ULL'for r in plan);kinds=','.join('1'if r['kind']=='file-copy-model'else'2'for r in plan)
(o/'model-fixtures.h').write_text('static const char*FileName[89]={'+','.join(files)+'};\nstatic const unsigned long long ModelBase[89]={'+bases+'},ModelBytes[89]={'+sizes+'};\nstatic const unsigned ModelKind[89]={'+kinds+'};\nstatic const unsigned long long Untouched[5][2]={'+holes+'};\nstatic const unsigned ExpectedReads='+str(expected_reads)+';\n')
native=json.loads(a.native.read_text());records=native['PAS_records'];assert native['memory_setup_accepted']and len(records)==2
(o/'native-API-fixtures.h').write_text('static const unsigned long long NativeStatus[2]={'+','.join(hex(x['OriginalStatus'])+'ULL'for x in records)+'};\nstatic const unsigned long long NativeResults[2][4]={'+','.join('{'+','.join(hex(v)+'ULL'for v in x['Results'])+'}'for x in records)+'};\n')
support=(verifier/'test-main-payload.c').read_text();assert support.count('\nint main(')==1
(o/'model-support.h').write_text(support.split('\nint main(')[0]+'\n')
r=Path('/home/PROJECT_USER.guest/woa-open/mu_aloha_platforms')
incs=[w,verifier,o,r/'MU_BASECORE/MdePkg/Include',r/'MU_BASECORE/MdePkg/Include/X64',r/'MU_BASECORE/MdeModulePkg/Include']
cmd=['cc','-std=c11','-D_GNU_SOURCE','-DOPEN_MAIN_ADMISSION_MODEL','-DNO_MSABI_VA_FUNCS','-fshort-wchar','-g','-O1','-Wall','-Wextra','-Werror','-Wno-parentheses','-fsanitize=address,undefined','-fno-omit-frame-pointer']+['-I'+str(x)for x in incs]+[str(w/'test-main-integration.c'),str(sequence/'OpenPasObserver.c'),str(w/'OpenMainAdmission.c'),'-o',str(o/'test')]
q=subprocess.run(['colima','ssh','--']+cmd,capture_output=True,text=True);(o/'compiler.txt').write_text(q.stdout+q.stderr);assert not q.returncode,q.stderr
cases=['success','copy-gcd-owner','pre-AT-last-fault','post-AT-last-fault','pre-demura','post-demura','owner-after-final-admit','hash-last','changed-untouched']
script='''import subprocess,json
rows=[]
for case in %r:
 r=subprocess.run([%r,%r,case],capture_output=True,text=True)
 if r.returncode or r.stderr:print(json.dumps({'case':case,'exit':r.returncode,'stdout':r.stdout,'stderr':r.stderr}));raise SystemExit(1)
 rows.append(json.loads(r.stdout))
print(json.dumps(rows))
'''%(cases,str(o/'test'),str(a.payload_dir.resolve()))
q=subprocess.run(['colima','ssh','--','python3','-c',script],capture_output=True,text=True);(o/'console.txt').write_text(q.stdout+q.stderr);assert not q.returncode,q.stdout+q.stderr
rows=json.loads(q.stdout);assert len(rows)==len(cases)
out={'passed':True,'cases':len(rows),'actual_PAS_main_admission_verifier_C':True,'real_SHA':True,'ASan_UBSan':True,'native_operations':0,
 'source_sha256':{n:sha((w/n).read_bytes()) for n in ['OpenMainAdmission.c','OpenMainAdmission.h','OpenMainAdmissionPlan.h','test-main-integration.c','test-main-integration.py']},
 'PAS_source_sha256':{n:sha((sequence/n).read_bytes()) for n in ['OpenPasObserver.c','OpenPasObserver.h']},
 'verifier_source_sha256':{n:sha((verifier/n).read_bytes()) for n in ['OpenMainPayload.c','OpenMainPayload.h','OpenMainPayloadPlan.h','OpenSha256.h','test-main-payload.c']},
 'model_report_sha256':sha(a.replay.read_bytes()),'historical_display_sha256':sha(a.display.read_bytes()),'expected_read_calls':expected_reads,'results':rows,
 'limits':['Actual admission, PAS policy, main verifier and SHA C are linked. Model RAM is pre-populated from captured files and exact original-replay extents; original loader writes are not executed in this combined test.',
 'UEFI map/allocation services, AT, MMIO, physical read access, protocol ownership, DTB AUTH/public return and all main secure replies remain modeled. Only DTB INIT/MEM status/results came from G144.',
 'No native main MEM_SETUP/copy/AUTH, global DMA/stage2 ownership, DSP/GLINK/charging or linked firmware qualification.']}
(o/'tests.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({k:v for k,v in out.items() if k not in ['source_sha256','results']},indent=2))
