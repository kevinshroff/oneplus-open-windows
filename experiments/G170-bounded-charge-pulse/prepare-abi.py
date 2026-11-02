"""Generate the Go schema, request fixtures and WDK assertions from actual C."""
from pathlib import Path
import argparse,json,subprocess
a=argparse.ArgumentParser();a.add_argument('--output',type=Path,required=True);args=a.parse_args()
w=Path(__file__).resolve().parent;p=args.output.resolve();p.mkdir(exist_ok=False)
subprocess.run(['clang','-std=c11','-Wall','-Wextra','-Werror','-I'+str(w/'native'),'-I'+str(w/'link'),str(w/'tests/abi.c'),'-o',str(p/'abi')],check=True)
r=subprocess.run([str(p/'abi'),str(p)],capture_output=True,text=True,check=True)
s=json.loads(r.stdout);(w/'client/abi.json').write_text(json.dumps(s,indent=2)+'\n')
for f in p.glob('*-request.bin'):(w/'client/testdata'/f.name).write_bytes(f.read_bytes())
checks=['/* Generated from actual C abi.c; cross-checked by ARM64 WDK compiler. */',f'C_ASSERT(sizeof(CLN_SNAPSHOT_DATA)=={s["size"]});',f'C_ASSERT(sizeof(CL_STATE)=={s["state_size"]});']
for table,typ in [('snapshot','CLN_SNAPSHOT_DATA'),('state','CL_STATE'),('batch','CL_BATCH'),('battery','CL_BATTERY')]:
 for n,off in s[table].items():checks.append(f'C_ASSERT(__builtin_offsetof({typ},{n})=={off});')
(w/'native/abi-checks.h').write_text('\n'.join(checks)+'\n')
print(json.dumps({'snapshot':s['size'],'state':s['state_size'],'assertions':len(checks)-1,'codes':s['codes']}))
