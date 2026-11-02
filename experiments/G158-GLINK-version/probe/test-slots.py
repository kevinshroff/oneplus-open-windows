from pathlib import Path
import argparse,hashlib,json,subprocess
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args()
w=Path(__file__).resolve().parent;o=a.output.resolve();o.mkdir(exist_ok=False,parents=True)
native=w.parent/'private/capture-model-01/part.bin'
q=subprocess.run(['clang','-std=c11','-O1','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I'+str(w),str(w/'test-slots.c'),'-o',str(o/'test-slots')],capture_output=True,text=True)
(o/'compiler.txt').write_text(q.stdout+q.stderr);assert q.returncode==0,q.stderr
q=subprocess.run([str(o/'test-slots'),str(native)],capture_output=True,text=True);(o/'run.txt').write_text(q.stdout+q.stderr);assert q.returncode==0,q.stdout+q.stderr
r=json.loads(q.stdout);r['source_sha256']={n:hashlib.sha256((w/n).read_bytes()).hexdigest()for n in ['g158_slots.h','test-slots.c']};r['native_G156_AP_ADSP_sample_sha256']=hashlib.sha256(native.read_bytes()).hexdigest();r['limits']=['Actual bounded parser with retained native data and mutations; no native writes or hardware ownership assertion.'];(o/'tests.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r,indent=2))
