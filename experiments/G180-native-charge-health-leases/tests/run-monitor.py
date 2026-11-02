"""Execute actual consumer/control bridge on frozen data and modeled peer IO."""
from pathlib import Path
import argparse,hashlib,json,subprocess
a=argparse.ArgumentParser();a.add_argument('--output',type=Path,required=True);a.add_argument('--captures',type=Path);args=a.parse_args();w=Path(__file__).resolve().parent.parent;o=args.output.resolve();o.mkdir(exist_ok=False)
old=args.captures.resolve()if args.captures else w.parent/'charging-G177/private';inputs=[old/'cycle-enabled-early-G167.bin',old/'cycle-enabled-early-G160.bin']
sources=[w/'tests/test-monitor.c',w/'link/health_monitor.c',w/'link/health_recheck.c',w/'link/health_capture.c',w/'link/link_core.c',w/'link/charger_codec.c']
r=subprocess.run(['clang','-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I'+str(w/'link'),*[str(f)for f in sources],'-o',str(o/'test-monitor')],capture_output=True,text=True);(o/'compiler.txt').write_text(r.stdout+r.stderr);assert not r.returncode,r.stderr
r=subprocess.run([str(o/'test-monitor'),*[str(f)for f in inputs]],capture_output=True,text=True);(o/'output.txt').write_text(r.stdout+r.stderr);assert not r.returncode,r.stdout+r.stderr
v=json.loads(r.stdout);sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest();v['source_sha256']={str(f.relative_to(w)):sha(f)for f in [*sources,w/'tests/test-link.c',w/'tests/peer.h',w/'link/health_monitor.h',w/'link/health_capture.h',w/'link/health_layout.h',w/'link/link_core.h',w/'link/charger_codec.h',Path(__file__).resolve()]};v['input_sha256']={str(f):sha(f)for f in inputs};(o/'tests.json').write_text(json.dumps(v,indent=2)+'\n');print({k:v[k]for k in ['passed','cases','native_operations','actual_core_and_monitor']})
