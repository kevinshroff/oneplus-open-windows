"""Actual C layout -> Go schema and native ARM64 WDK assertions."""
from pathlib import Path
import argparse,json,subprocess
a=argparse.ArgumentParser();a.add_argument('--output',type=Path,required=True);args=a.parse_args();w=Path(__file__).resolve().parent;o=args.output.resolve();o.mkdir(exist_ok=False)
subprocess.run(['clang','-std=c11','-Wall','-Wextra','-Werror','-I'+str(w/'source'),str(w/'tests/abi.c'),'-o',str(o/'abi')],check=True)
s=json.loads(subprocess.check_output([str(o/'abi')],text=True));(w/'client/abi.json').write_text(json.dumps(s,indent=2)+'\n');checks=['/* Generated actual C schema, verified again by native ARM64 WDK. */']
for t,k in [('G179_STATUS','status_size'),('G179_CAPTURE','capture_size'),('G179_REQUEST','request_size'),('CH_IO_RESULT','io_size'),('CH_HEALTH','health_size')]:checks.append(f'C_ASSERT(sizeof({t})=={s[k]});')
for table,t in [('status','G179_STATUS'),('capture','G179_CAPTURE'),('io','CH_IO_RESULT'),('health','CH_HEALTH')]:
 for n,off in s[table].items():checks.append(f'C_ASSERT(FIELD_OFFSET({t},{n})=={off});')
(w/'source/abi-checks.h').write_text('\n'.join(checks)+'\n');print({'status_bytes':s['status_size'],'capture_bytes':s['capture_size'],'assertions':len(checks)-1,'codes':s['codes']})
