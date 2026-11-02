from pathlib import Path
import argparse,subprocess,json,hashlib
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();o=a.output.resolve();assert not o.exists();o.mkdir(parents=True);w=Path(__file__).resolve().parent
exe=o/'test';q=subprocess.run(['clang','-std=c11','-O1','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I',str(w),str(w/'g101_core.c'),str(w/'test-core.c'),'-o',str(exe)],capture_output=True,text=True);assert not q.returncode,q.stderr
q=subprocess.run([str(exe)],capture_output=True,text=True);assert not q.returncode and not q.stderr,(q.stdout,q.stderr);r=json.loads(q.stdout);r['ASan_UBSan']=True;r['source_sha256']={n:hashlib.sha256((w/n).read_bytes()).hexdigest()for n in ['g101_core.c','g101_core.h','g101_resources.h','test-core.c']};(o/'tests.json').write_text(json.dumps(r,indent=2));print(json.dumps(r))
