"""Compare original compiled query bytes with the new read-only codec."""
from pathlib import Path
import argparse,hashlib,json,struct,subprocess
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();w=Path(__file__).resolve().parent;o=a.output.resolve();o.mkdir(exist_ok=False,parents=True)
proof=json.loads((w.parent/'private/original-queries-01.json').read_text());assert proof['passed']and proof['cases']==23
frames=[]
for kind in ['static','state','voltage','status']:
 row=next(x for x in proof['results']if x['kind']==kind and not x['null_output']and x['transport_status_model']=='0x0'and x['index_fixture']==0)
 words=row['events'][0]['words'];frames.append(struct.pack('<'+str(len(words))+'I',*words))
(o/'original-queries.h').write_text('static const unsigned OriginalBytes[4]={'+','.join(str(len(b))for b in frames)+'};\nstatic const uint8_t OriginalRequests[4][24]={'+','.join('{'+','.join(hex(x)for x in b)+'}'for b in frames)+'};\n')
q=subprocess.run(['clang','-std=c11','-O1','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I'+str(w),'-I'+str(o),str(w/'test-codec.c'),str(w/'g159_codec.c'),'-o',str(o/'test')],capture_output=True,text=True);(o/'compiler.txt').write_text(q.stdout+q.stderr);assert q.returncode==0,q.stderr
q=subprocess.run([str(o/'test')],capture_output=True,text=True);(o/'run.txt').write_text(q.stdout+q.stderr);assert q.returncode==0,q.stdout+q.stderr
r=json.loads(q.stdout);r.update(source_sha256={n:hashlib.sha256((w/n).read_bytes()).hexdigest()for n in ['g159_codec.c','g159_codec.h','test-codec.c']},original_PE_request_bytes_cross_checked=True,limits=['Compiled originals establish four exact query frames. Additional fixed property GETs use the retained Linux protocol reference; native support remains unverified.','No native request, battery reading, property setter or calibration.']);(o/'tests.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r,indent=2))
