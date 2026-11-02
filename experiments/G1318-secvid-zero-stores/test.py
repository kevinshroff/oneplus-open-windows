#!/usr/bin/env python3
"""Actual G456 body/table CPU qualification; no firmware, device or Windows ABI."""
from pathlib import Path
import argparse,json,subprocess,tempfile
W=Path(__file__).resolve().parent;B=W.parent/'G1287-cold-aperture';R=B/'reference/runtime'
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--cc',default='clang');a=p.parse_args()
source=(R/'g456_hwinit.c').read_text()
# Only dependency includes are replaced. All production function bodies/tables
# and the real facts/report definitions are compiled unchanged.
source=source.replace('#include "gpu_owner.h"','#include "host.h"').replace('#include "g433_runtime.h"','').replace('#include <intrin.h>','')
header=(R/'g456_hwinit.h').read_text();types=header[header.index('typedef struct {ULONGLONG Generation'):header.index('NTSTATUS G456ValidateFacts')]
with tempfile.TemporaryDirectory(prefix='g1318-') as tmp:
    out=Path(tmp)
    (out/'host.h').write_text('#pragma once\n'+(W/'tests/host_types.h').read_text()+types+(W/'tests/host_runtime.h').read_text())
    (out/'actual.c').write_text(source)
    results=[]
    for mode in (0,1):
        exe=out/f'actor-{mode}'
        args=[a.cc,'-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',
              '-fno-sanitize-recover=all',f'-DOGO_GPU_SECVID_ZERO_STORES={mode}',
              '-I'+str(out),'-I'+str(R),str(out/'actual.c'),str(W/'tests/test_executor.c'),'-o',str(exe)]
        subprocess.run(args,check=True)
        q=subprocess.run([str(exe)],check=True,text=True,capture_output=True);results.append(json.loads(q.stdout))
    baseline,variant=results
    assert variant['writes'][:4]==[[0,0x3e00c,0],[0,0x3e000,0],[0,0x3e004,0],[0,0x3e008,0]]
    assert variant['writes'][4:]==baseline['writes'],'unexpected write delta/order'
    for mode in ('2','-1'):
        q=subprocess.run([a.cc,'-x','c','-fsyntax-only',f'-DOGO_GPU_SECVID_ZERO_STORES={mode}',
                          '-include',str(R/'g456_secvid_zero.h'),'-'],input='',capture_output=True,text=True)
        assert q.returncode!=0 and 'must be exactly 0 or 1' in q.stderr
    print(json.dumps(dict(native_evidence=False,ASan_UBSan=True,baseline_cases=baseline['cases'],
                         variant_cases=variant['cases'],baseline_writes=len(baseline['writes']),
                         variant_writes=len(variant['writes']),only_delta=variant['writes'][:4],invalid_option_cases=2)))
