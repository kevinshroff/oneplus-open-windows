"""Create an analysis-only ELF view for AOP Cortex-M local memory aliases.

The stock image stores ITCM/DTCM system addresses (0x0b000000/0x0b0e0000).
The reset vector is 0x9, SP is 0x18000, and absolute Thumb function pointers
use the local 0..0x17fff region. Preserve each segment's original bytes and
physical destination; change only ELF virtual-address/entry metadata for analysis.
This derived image must never be flashed or substituted for the stock firmware.
"""
from pathlib import Path
import argparse, hashlib, json, struct

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--source',required=True,type=Path)
p.add_argument('--output',required=True,type=Path)
a=p.parse_args()
b=bytearray(a.source.read_bytes())
assert hashlib.sha256(b).hexdigest()=='e212e15ae63f5352ad3a7bd09429746177cdedd7582f242a56891def9af849e6'
assert not a.output.exists()
assert b[:7]==b'\x7fELF\x01\x01\x01'
phoff=struct.unpack_from('<I',b,28)[0];phsize,n=struct.unpack_from('<HH',b,42)
changes=[]
entry=struct.unpack_from('<I',b,24)[0]
assert entry==0x0b000009
struct.pack_into('<I',b,24,9)
changes.append(dict(field='entry',offset=24,before=hex(entry),after='0x9'))
segments=[]
for i in range(n):
 o=phoff+i*phsize
 typ,off,va,pa,filesz,memsz,flags,align=struct.unpack_from('<8I',b,o)
 if typ!=1:continue
 local=va-0x0b000000 if va in (0x0b000000,0x0b0e0000) else va
 if local!=va:
  struct.pack_into('<I',b,o+8,local)
  changes.append(dict(field='p_vaddr',segment=i,offset=o+8,before=hex(va),after=hex(local)))
 segments.append(dict(index=i,physical_address=hex(pa),analysis_virtual_address=hex(local),file_offset=off,file_bytes=filesz,segment_sha256=hashlib.sha256(b[off:off+filesz]).hexdigest()))
assert struct.unpack_from('<II',b,340)==(0x18000,9)
a.output.write_bytes(b)
r=dict(source=str(a.source),source_sha256=hashlib.sha256(a.source.read_bytes()).hexdigest(),output=str(a.output),output_sha256=hashlib.sha256(b).hexdigest(),changes=changes,segments=segments,authority='derived analysis view only',limitations=['Local Cortex-M alias inference from vector/function-pointer evidence; not a modified bootable firmware.','No code or data segment bytes changed; physical destinations retained.'])
a.output.with_suffix('.json').write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps(dict(changes=changes,output_sha256=r['output_sha256'])))
