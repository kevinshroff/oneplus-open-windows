"""Derive provider-result offsets from exact source; no native call."""
from pathlib import Path
import hashlib,json,subprocess
import argparse
a=argparse.ArgumentParser();a.add_argument('--output',type=Path);a.add_argument('--g160-source',type=Path);a.add_argument('--g167-source',type=Path);args=a.parse_args()
w=Path(__file__).resolve().parent;p=args.output.resolve()if args.output else w/'private/health-layout';p.mkdir(exist_ok=False)
g160=args.g160_source or w.parent/'charging-G160/probe';g167=args.g167_source or w.parent/'charging-G167/probe'
source=r'''
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
typedef uint32_t ULONG;typedef uint64_t ULONGLONG;
#define C_ASSERT(x) _Static_assert(x,#x)
#define FIELD_OFFSET(t,n) offsetof(t,n)
#define CTL_CODE(t,f,m,a) (((t)<<16)|((a)<<14)|((f)<<2)|(m))
#define FILE_DEVICE_UNKNOWN 0x22u
#define METHOD_BUFFERED 0
#define FILE_READ_ACCESS 1
#define FILE_WRITE_ACCESS 2
#include "g104_core.h"
#include "g160_protocol.h"
#include "g167_protocol.h"
int main(void){printf("{\"gauge_after\":%zu,\"gauge_trace\":%zu,\"gauge_values\":%zu,\"config_values\":%zu,\"config_trace\":%zu,\"g160_bytes\":%zu,\"g167_bytes\":%zu,\"g160_RESULT\":%u,\"g167_RESULT\":%u}\n",offsetof(G104_RESULT,After),offsetof(G104_RESULT,Trace),offsetof(G104_RESULT,Values),offsetof(G111_RESULT,Values),offsetof(G111_RESULT,Trace),sizeof(G160_CAPTURE),sizeof(G167_CAPTURE),G160_IOCTL_RESULT,G167_IOCTL_RESULT);}
'''
(p/'layout.c').write_text(source)
subprocess.run(['clang','-std=c11','-Werror','-Wall','-Wextra','-I'+str(g160),'-I'+str(g167),str(p/'layout.c'),'-o',str(p/'layout')],check=True)
v=json.loads(subprocess.check_output([str(p/'layout')],text=True))
assert v['g160_bytes']==279880 and v['g167_bytes']==1096 and v['gauge_values']==80 and v['config_values']==64 and v['config_trace']==216
(w/'link/health_layout.h').write_text('/* Generated from exact provider source C layout. */\n#ifndef G178_HEALTH_LAYOUT_H\n#define G178_HEALTH_LAYOUT_H\n#define G178_GAUGE_AFTER '+str(v['gauge_after'])+'u\n#define G178_GAUGE_TRACE '+str(v['gauge_trace'])+'u\n#endif\n')
v['source_sha256']={str(f):hashlib.sha256(f.read_bytes()).hexdigest()for d in [g160,g167]for f in d.iterdir()if f.suffix in ['.h']}
(p/'proof.json').write_text(json.dumps(v,indent=2)+'\n');print({k:v[k]for k in v if k!='source_sha256'})
