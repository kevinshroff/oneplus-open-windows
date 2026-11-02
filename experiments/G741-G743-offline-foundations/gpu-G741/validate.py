#!/usr/bin/env python3
"""Offline host fault injection + ARM64 object compilation. Never links/runs a driver."""
from pathlib import Path
import json, subprocess
here = Path(__file__).resolve().parent
host = ['clang','-std=c11','-Wall','-Wextra','-Werror','-Wno-multichar',
        '-fsanitize=address,undefined','-pthread','-I'+str(here/'tests'),
        '-I'+str(here/'source'),str(here/'source/a740_hal.c'),
        str(here/'tests/test_hal.c'),'-o',str(here/'build/test_hal')]
subprocess.run(host, check=True)
r = subprocess.run([str(here/'build/test_hal')], capture_output=True, text=True, check=True)
(here/'build/host-test.log').write_text(r.stdout+r.stderr)
print(r.stdout, end='')
rows = json.loads((here/'build/compile.json').read_text())
for row in rows:
    r = subprocess.run(row['argv'], capture_output=True, text=True)
    row['returncode'] = r.returncode
    (here/'build'/(Path(row['source']).stem+'.log')).write_text(r.stdout+r.stderr)
    if r.returncode:
        raise RuntimeError(row['source']+': '+r.stderr)
    assert (here/'build'/(Path(row['source']).stem+'.obj')).read_bytes()[:2] == b'\x64\xaa'
(here/'build/compile.json').write_text(json.dumps(rows,indent=2)+'\n')
print('PASS: all 9 ARM64 COFF translation units, WDK -Wall -Wextra -Werror')
