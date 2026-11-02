from pathlib import Path
import argparse,subprocess,json,hashlib
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True);w=Path(__file__).resolve().parent
files=['g99_core.c','g99_core.h','test-core.c'];sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();before={n:sha(w/n)for n in files};exe=a.output/'test';q=subprocess.run(['clang','-std=c11','-O1','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I',str(w),str(w/'g99_core.c'),str(w/'test-core.c'),'-o',str(exe)],capture_output=True,text=True);assert not q.returncode,q.stderr
q=subprocess.run([str(exe.resolve())],capture_output=True,text=True);assert not q.returncode and not q.stderr,(q.stdout,q.stderr);v=json.loads(q.stdout);assert before=={n:sha(w/n)for n in files};v.update(source_sha256=before,ASan_UBSan=True);(a.output/'tests.json').write_text(json.dumps(v,indent=2)+'\n');print(json.dumps(v))
