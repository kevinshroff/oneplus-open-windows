"""Offline ABI/capability-scope audit; no debugger or target access."""
import hashlib
import json
import re
import sys
from pathlib import Path

src = Path(__file__).with_name('probe_windows.go').read_text()
header = Path(sys.argv[1]).read_text()
expected = {
 'IDebugControl': {34:'GetDebuggeeType',35:'GetActualProcessorType',47:'GetEffectiveProcessorType',49:'GetExecutionStatus',68:'GetNumberBreakpoints',72:'AddBreakpoint',73:'RemoveBreakpoint'},
 'IDebugBreakpoint': {4:'GetType',6:'GetFlags',12:'GetDataParameters',13:'SetDataParameters'},
 'IDebugClient': {21:'ConnectSession'},
}
for interface, methods in expected.items():
 start=header.index('DECLARE_INTERFACE_('+interface+', IUnknown)')
 body=header[start:header.index('\n};',start)]
 names=re.findall(r'STDMETHOD(?:V)?(?:_\([^,]+,\s*|\()([A-Za-z0-9_]+)\)',body)
 for slot,name in methods.items():
  assert names[slot]==name,(interface,slot,name,names[slot])
allowed={'ctl':{2,34,35,47,49,68,72,73},'bp':{4,6,12,13},'client':{0,2,21}}
calls=re.findall(r'call\((ctl|bp|client),\s*(\d+)',src)
assert calls
for obj,slot in calls:
 assert int(slot) in allowed[obj],(obj,slot)
assert 'probe(ctl, 1), probe(ctl, 4)' in src
assert 'if before != 0' in src
assert 'a.Flags&4 != 0' in src
assert 'defer func()' in src and 'RemoveBreakpoint(owned disabled object)' in src
assert '0xad, 0x92, 0x24, 0xef, 0x80, 0x04, 0x24, 0xba' in src
print(json.dumps({'sdk_slots_match':True,'only_disabled_breakpoint_parameter_methods':True,'source_sha256':hashlib.sha256(src.encode()).hexdigest(),'runtime_tested':False},indent=2))
