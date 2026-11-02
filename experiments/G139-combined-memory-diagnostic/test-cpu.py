from pathlib import Path
import argparse,hashlib,json,subprocess
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args()
w=Path(__file__).resolve().parent;a.output.mkdir(exist_ok=False)
r=subprocess.run(['cc','-std=c11','-O1','-g','-fsanitize=address,undefined','-fno-omit-frame-pointer','-Wall','-Wextra','-Werror',str(w/'test-cpu.c'),'-o',str(a.output.resolve()/'test')],capture_output=True,text=True)
(a.output/'compiler.txt').write_text(r.stdout+r.stderr);assert r.returncode==0,r.stderr
r=subprocess.run([str(a.output.resolve()/'test')],capture_output=True,text=True)
(a.output/'console.txt').write_text(r.stdout+r.stderr);assert r.returncode==0,r.stdout+r.stderr
report=json.loads(r.stdout);assert report['passed'] and report['cases']==15
report.update(ASan_UBSan=True,actual_portable_C=True,models=['AT callback returns explicitly modeled PAR values; no native translation instruction executes.'],source_sha256={n:hashlib.sha256((w/n).read_bytes()).hexdigest() for n in ['OpenPilCpuInventory.c','OpenPilCpuInventory.h','test-cpu.c']})
(a.output/'tests.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
