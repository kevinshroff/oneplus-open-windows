"""Explicit small offline view to seed the original default-property getter.
No native action. Does not substitute reconstructed bytes for running firmware.
"""
from pathlib import Path
import argparse,hashlib,json,struct
p=argparse.ArgumentParser();p.add_argument('--input',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
raw=a.input.read_bytes();sha=lambda b:hashlib.sha256(b).hexdigest()
assert sha(raw)=='96dec3f35f9bd2fff7edce48d280d0cefc16e1029f969df8b8a9a41f8c3b5507'
h=list(struct.unpack_from('<16sHHIIIIIHHHHHH',raw));rows=[struct.unpack_from('<8I',raw,h[5]+32*i)for i in range(h[10])]
regions=[(0x60065000,0x2000,5),(0x6021f000,0x4000,4)]
new=bytearray(4096);notes=[]
for i,(address,size,flags)in enumerate(regions):
 matches=[r for r in rows if r[2]<=address and address+size<=r[2]+r[4]];assert len(matches)==1;r=matches[0];start=r[1]+address-r[2];b=raw[start:start+size];assert len(b)==size
 offset=len(new);new.extend(b);struct.pack_into('<8I',new,52+32*i,1,offset,address,r[3]+address-r[2],size,size,flags,4096)
 notes.append({'virtual':hex(address),'bytes':size,'original_file_offset':start,'payload_sha256':sha(b)})
h[4]=0x60065d00;h[5]=52;h[10]=len(regions);h[6]=h[11]=h[12]=h[13]=0;struct.pack_into('<16sHHIIIIIHHHHHH',new,0,*h)
a.output.mkdir(exist_ok=False,parents=True);(a.output/'fallback-getter-analysis.elf').write_bytes(new)
report={'parent_sha256':sha(raw),'view_sha256':sha(new),'view_bytes':len(new),'analyst_entry':'0x60065d00','regions':notes,'limits':['Exact code/rodata bytes and virtual addresses from pinned split firmware. Analyst headers, file offsets and entry. Other code, initialized globals, BSS and runtime bindings deliberately omitted.','Does not establish selected runtime platform, callee effects, execution, ownership or charger control.'],'native_operations':0}
(a.output/'report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
