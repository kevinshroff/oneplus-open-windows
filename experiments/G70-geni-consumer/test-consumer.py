"""Fault/ownership checks of the actual consumer, never native hardware."""
from pathlib import Path
import argparse,hashlib,json,subprocess
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();W=Path(__file__).resolve().parent;assert not a.output.exists();a.output.mkdir(parents=True);exe=a.output/'consumer-model'
q=subprocess.run(['clang','-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-fno-omit-frame-pointer','-I'+str(W),str(W/'test-consumer.c'),str(W/'g70_consumer.c'),str(W/'g70_clock.c'),'-o',str(exe)],capture_output=True,text=True);assert not q.returncode,(q.stdout,q.stderr)
q=subprocess.run([str(exe)],capture_output=True,text=True);assert not q.returncode and not q.stderr,(q.stdout,q.stderr);r=json.loads(q.stdout);r.update(source_sha256={n:hashlib.sha256((W/n).read_bytes()).hexdigest()for n in ['test-consumer.c','test-clock.c','g70_consumer.c','g70_consumer.h','g70_clock.c','g70_clock.h','g70_protocol.h']},sanitizers=['AddressSanitizer','UndefinedBehaviorSanitizer']);(a.output/'tests.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r))
