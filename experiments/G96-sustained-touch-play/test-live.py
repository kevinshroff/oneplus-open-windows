"""Exercise the real bounded live pump and Windows lifecycle under failure."""
from pathlib import Path
import argparse,hashlib,json,subprocess
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True);W=Path(__file__).resolve().parent
names=['g96_input.c','g96hid_lifecycle.c','g96_report.c','g96_poll.c','test-live.c'];exe=a.output/'test'
source_names=names+['g96_input.h','g96hid_lifecycle.h','g96_report.h','g96_poll.h','test-fixtures.h'];initial_sha={n:hashlib.sha256((W/n).read_bytes()).hexdigest()for n in source_names}
q=subprocess.run(['clang','-std=c11','-O1','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',*[str(W/n)for n in names],'-o',str(exe.resolve())],capture_output=True,text=True);assert not q.returncode,q.stderr
q=subprocess.run([str(exe.resolve())],capture_output=True,text=True);assert not q.returncode and not q.stderr,(q.stdout,q.stderr);r=json.loads(q.stdout);assert initial_sha=={n:hashlib.sha256((W/n).read_bytes()).hexdigest()for n in source_names},'Source changed during test';r.update(ASan_UBSan=True,source_sha256={n:hashlib.sha256((W/n).read_bytes()).hexdigest()for n in names+['g96_input.h','g96hid_lifecycle.h','g96_report.h','g96_poll.h','test-fixtures.h']},native_access=False,limits=['Transport, clock, clear completion and VHF acceptance are modeled.','The compiled source contains no native MMIO adapter, WDF device or real Windows consumer.'])
(a.output/'tests.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r))
