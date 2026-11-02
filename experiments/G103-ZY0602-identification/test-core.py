from pathlib import Path
import argparse,subprocess,json,hashlib
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();o=a.output.resolve();assert not o.exists();o.mkdir(parents=True);w=Path(__file__).resolve().parent
q=subprocess.run(['clang','-std=c11','-O1','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I',str(w),str(w/'g102_core.c'),str(w/'g103_core.c'),str(w/'test-core.c'),'-o',str(o/'test')],capture_output=True,text=True);assert not q.returncode,q.stderr
q=subprocess.run([str(o/'test')],capture_output=True,text=True);assert not q.returncode and not q.stderr,(q.stdout,q.stderr)
r=json.loads(q.stdout.strip().splitlines()[-1]);r['ASan_UBSan']=True;r['source_sha256']={n:hashlib.sha256((w/n).read_bytes()).hexdigest()for n in ['g102_core.c','g102_core.h','g102_resources.h','g103_core.c','g103_core.h','g103_policy.h','test-core.c']};(o/'tests.json').write_text(json.dumps(r,indent=2)+'\n');print(q.stdout)
