"""Append one namespace canary to the captured DSDT; preserve its existing AML exactly."""
from pathlib import Path
import hashlib
import json
import struct
import sys

source, out = Path(sys.argv[1]), Path(sys.argv[2])
b = source.read_bytes()
assert b[:4] == b'DSDT' and len(b) == struct.unpack_from('<I',b,4)[0]
assert hashlib.sha256(b).hexdigest() == 'c8ef19940f424fce18a6e56580493629accb7c59a9ae495cc42c9445029f3e01'
assert sum(b)%256 == 0 and b'G20C' not in b
payload = b'\x08G20C\x0c'+struct.pack('<I',0x47323043)
a = bytearray(b+payload)
struct.pack_into('<I',a,4,len(a))
struct.pack_into('<I',a,24,struct.unpack_from('<I',b,24)[0]+1)
a[9] = 0
a[9] = (-sum(a))&255
assert a[36:len(b)] == b[36:] and sum(a)%256 == 0 and len(payload)==10
if out.exists():
    assert out.read_bytes() == a, 'refuse to overwrite another artifact'
else:
    out.write_bytes(a)
r = {'source_sha256':hashlib.sha256(b).hexdigest(),'after_sha256':hashlib.sha256(a).hexdigest(),
     'before_bytes':len(b),'after_bytes':len(a),'all_existing_AML_body_bytes_unchanged':True,
     'OEM_revision_before':struct.unpack_from('<I',b,24)[0],'OEM_revision_after':struct.unpack_from('<I',a,24)[0],
     'header_changes':['Length','Checksum','OEM Revision'],'appended_AML_hex':payload.hex(),
     'canary_namespace':'\\G20C','canary_integer':'0x47323043','added_GPIO_or_other_device':False,
     'deployment':'offline preparation only; no native override tested by this builder'}
(out.parent/'canary-table-receipt.json').write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps(r,indent=2))
