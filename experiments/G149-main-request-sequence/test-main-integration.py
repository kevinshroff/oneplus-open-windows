"""Run the actual verifier and inherited SHA core against captured-file model RAM."""
from pathlib import Path
import argparse,hashlib,json,subprocess
w=Path(__file__).resolve().parent;p=argparse.ArgumentParser()
p.add_argument('--verifier-root',type=Path,default=w.parent/'charging-G148')
p.add_argument('--native',type=Path,default=w.parent/'charging-G144/private/native-analysis.json')
p.add_argument('--replay',type=Path,default=w.parent/'charging-G147/private/main-target-replay-04.json')
p.add_argument('--layout',type=Path,default=w.parent/'charging-G147/private/main-layout-summary.json')
p.add_argument('--payload-dir',type=Path,default=w.parent/'charging-G118/private/firmware-input/firmware/image')
p.add_argument('--output',type=Path,required=True);a=p.parse_args();verifier=a.verifier_root.resolve();o=a.output.resolve();o.mkdir(parents=True,exist_ok=False)
sha=lambda b:hashlib.sha256(b).hexdigest()
assert sha(a.replay.read_bytes())=='c92416ad0eec6d8d87dd0d483238472bf5f8a53218911e590c72147e72145236'
j=json.loads(a.replay.read_text());assert j['passed']and j['cases']==8
assert sha((verifier/'OpenSha256.h').read_bytes())=='33b1ac0bab27454237686000ee66f8c9604c68fbaa90bc06545ca089e2dac227'
for name,h in j['payload_inputs_sha256'].items():assert sha((a.payload_dir/name).read_bytes())==h,name
plan=j['complete_target_plan'];layout=json.loads(a.layout.read_text());assert layout['source_report_sha256']==sha(a.replay.read_bytes())and layout['write_overlaps_bytes']==0
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
incs=[w,verifier,o,r/'MU_BASECORE/MdePkg/Include',r/'MU_BASECORE/MdePkg/Include/X64']
cmd=['cc','-std=c11','-D_GNU_SOURCE','-DNO_MSABI_VA_FUNCS','-fshort-wchar','-g','-O1','-Wall','-Wextra','-Werror','-Wno-parentheses','-fsanitize=address,undefined','-fno-omit-frame-pointer']+['-I'+str(x)for x in incs]+[str(w/'test-main-integration.c'),str(w/'OpenPasObserver.c'),'-o',str(o/'test')]
q=subprocess.run(['colima','ssh','--']+cmd,capture_output=True,text=True);(o/'compiler.txt').write_text(q.stdout+q.stderr);assert not q.returncode,q.stderr
q=subprocess.run(['colima','ssh','--',str(o/'test'),str(a.payload_dir.resolve())],capture_output=True,text=True);(o/'console.txt').write_text(q.stdout+q.stderr);assert not q.returncode,q.stdout+q.stderr
rows=[json.loads(x)for x in q.stdout.splitlines()];out=rows[-1];assert out['passed']and out['cases']==4
out.update(source_sha256={n:sha((w/n).read_bytes())for n in ['OpenPasObserver.c','OpenPasObserver.h','test-main-integration.c','test-main-integration.py']},verifier_source_sha256={n:sha((verifier/n).read_bytes())for n in ['OpenMainPayload.c','OpenMainPayload.h','OpenMainPayloadPlan.h','OpenSha256.h','test-main-payload.c']},model_report_sha256=sha(a.replay.read_bytes()),expected_read_calls=expected_reads,results=rows[:-1],limits=['Actual PAS policy, main verifier and SHA C; main RAM is populated from captured files and independent original-replay extents.','Only DTB INIT/MEM status/results came from G144; DTB AUTH/public completion, all main secure replies and physical admission/owner/read callbacks remain modeled.','No native main load, AUTH, memory ownership, DSP/GLINK/charging or firmware integration qualification.'])
(o/'tests.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({k:v for k,v in out.items()if k not in ['source_sha256','results']},indent=2))
