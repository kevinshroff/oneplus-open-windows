"""Exercise actual bounded poll core with a real captured contact and fault callbacks."""
import argparse,hashlib,json,subprocess
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--contact',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True);W=Path(__file__).resolve().parent
b=a.contact.read_bytes();assert len(b)==26 and b[0]==0x80 and b[2]==1
(a.output/'poll-input.h').write_text('static const uint8_t Contact[26]={'+','.join(map(str,b))+'};\n')
exe=a.output/'poll';q=subprocess.run(['clang','-std=c11','-O1','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I',str(W),'-I',str(a.output.resolve()),str(W/'g53_poll.c'),str(W/'g53_report.c'),str(W/'test-poll.c'),'-o',str(exe.resolve())],capture_output=True,text=True);assert q.returncode==0,q.stderr
q=subprocess.run([str(exe.resolve())],capture_output=True,text=True);assert q.returncode==0 and not q.stderr,(q.stdout,q.stderr)
r=json.loads(q.stdout);r.update(ASan_UBSan=True,source_sha256={n:hashlib.sha256((W/n).read_bytes()).hexdigest()for n in ['g53_poll.c','g53_report.c','test-poll.c']},captured_contact_sha256=hashlib.sha256(b).hexdigest(),native_actions=0)
(a.output/'tests.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r))
