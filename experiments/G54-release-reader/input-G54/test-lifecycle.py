import argparse,hashlib,json,subprocess
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--output',required=True,type=Path);a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True);W=Path(__file__).resolve().parent
exe=a.output/'test';sources=[W/'g54_lifecycle.c',W/'test-lifecycle.c',W.parent/'reader-G54/g54_report.c']
r=subprocess.run(['clang','-std=c11','-O2','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',*map(str,sources),'-o',str(exe.resolve())],capture_output=True,text=True);assert r.returncode==0,r.stderr
r=subprocess.run([str(exe.resolve())],capture_output=True,text=True);assert r.returncode==0 and not r.stderr,(r.stdout,r.stderr);j=json.loads(r.stdout);j.update(ASan_UBSan=True,source_sha256={str(p.relative_to(W.parent)):hashlib.sha256(p.read_bytes()).hexdigest()for p in sources+[W/'g54_lifecycle.h',W.parent/'reader-G54/g54_report.h']},native_actions=0,limits=['Models raw packets and submit acceptance; no real HID consumer or VHF device is exercised.','Physical descriptor dimensions and unique child binding still need implementation/native qualification.'])
(a.output/'tests.json').write_text(json.dumps(j,indent=2)+'\n');print(json.dumps(j))
