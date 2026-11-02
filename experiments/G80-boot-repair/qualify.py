from pathlib import Path
import subprocess,json,hashlib,os
W=Path(__file__).resolve().parents[1];S=W/'scripts';results={}
def run(name,argv,**kw):
 p=subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,**kw);results[name]={'argv':argv,'exit_code':p.returncode,'output':p.stdout};print(name,p.stdout.strip(),flush=True);assert p.returncode==0
run('compile_pinned',['clang','-fsanitize=address,undefined','-g','-O1',str(S/'test-pinned.c'),'-o',str(W/'private/test-pinned')]);run('pinned_failure_injection',[str(W/'private/test-pinned')])
G='/home/PROJECT_USER.guest/woa-open/mu_aloha_platforms'
cmd='cd '+G+' && gcc -fshort-wchar -fsanitize=address,undefined -I MU_BASECORE/MdePkg/Include -I MU_BASECORE/MdePkg/Include/X64 -I '+str(S)+' '+str(S/'test-gpt.c')+' '+str(S/'OpenG80GptTypeMigration.c')+' -lz -o /tmp/G80-gpt-final && /tmp/G80-gpt-final '+str(W/'private')
run('actual_firmware_gpt_failure_injection',['colima','ssh','--','bash','-lc',cmd])
run('host_protocol',['go','test','-race','./...'],cwd=S/'scsi-prefix')
results['source_sha256']={str(p.relative_to(S)):hashlib.sha256(p.read_bytes()).hexdigest() for p in S.rglob('*') if p.is_file() and p.suffix in ['.go','.c','.h']}
(W/'captures/native-qualification.json').write_text(json.dumps(results,indent=2))
