"""Execute the actual WDF adapter against API contracts, never native hardware."""
from pathlib import Path
import argparse,hashlib,json,subprocess
p=argparse.ArgumentParser();p.add_argument('--binding',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();W=Path(__file__).resolve().parent;assert not a.output.exists();a.output.mkdir(parents=True);exe=a.output/'driver-model'
q=subprocess.run(['clang','-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-fno-omit-frame-pointer','-pthread','-I'+str(W/'model-headers'),'-I'+str(a.binding),'-I'+str(W),str(W/'test-driver.c'),str(W/'g69_clock.c'),'-o',str(exe)],capture_output=True,text=True);assert not q.returncode,(q.stdout,q.stderr)
q=subprocess.run([str(exe),str(a.output/'MODEL-NOT-NATIVE.bin')],capture_output=True,text=True);assert not q.returncode and not q.stderr,(q.stdout,q.stderr)
v=json.loads(q.stdout);v.update(driver_source_sha256=hashlib.sha256((W/'g69_driver.c').read_bytes()).hexdigest(),binding_sha256=hashlib.sha256((a.binding/'g69_binding.h').read_bytes()).hexdigest(),model_packet_sha256=hashlib.sha256((a.output/'MODEL-NOT-NATIVE.bin').read_bytes()).hexdigest(),sanitizers=['AddressSanitizer','UndefinedBehaviorSanitizer'])
(a.output/'tests.json').write_text(json.dumps(v,indent=2)+'\n');print(json.dumps(v))
