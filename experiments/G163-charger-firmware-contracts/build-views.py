"""Small exact-byte offline DSP views for REA. No firmware/native mutation."""
from pathlib import Path
import argparse,hashlib,json,struct
p=argparse.ArgumentParser();p.add_argument('--input',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
raw=a.input.read_bytes();sha=lambda b:hashlib.sha256(b).hexdigest()
assert sha(raw)=='96dec3f35f9bd2fff7edce48d280d0cefc16e1029f969df8b8a9a41f8c3b5507'
h=list(struct.unpack_from('<16sHHIIIIIHHHHHH',raw));rows=[struct.unpack_from('<8I',raw,h[5]+32*i)for i in range(h[10])]
views={
 'FV':(0x60059e90,[(0x60059000,0x4000,5),(0x60220000,0x15000,4)]),
 'Power4':(0x6005a400,[(0x60059000,0x4000,5),(0x60220000,0x15000,4)]),
 'Power3':(0x60043a90,[(0x60043000,0x2000,5),(0x60220000,0x15000,4)]),
 'GaugeRead':(0x601d1cc0,[(0x601d1000,0x2000,5),(0x60288000,0x1a000,4)]),
 'ChgCtl':(0x60171ad0,[(0x60170000,0x6000,5),(0x60260000,0x20000,4)]),
 'Schg':(0x600b85a0,[(0x600b0000,0x10000,5),(0x60240000,0x12000,4)]),
}
a.output.mkdir(exist_ok=False,parents=True)
for name,(entry,regions)in views.items():
 new=bytearray(4096);notes=[]
 for i,(address,size,flags)in enumerate(regions):
  matches=[r for r in rows if r[2]<=address and address+size<=r[2]+r[4]];assert len(matches)==1;r=matches[0];start=r[1]+address-r[2];data=raw[start:start+size];assert len(data)==size
  offset=len(new);new.extend(data);struct.pack_into('<8I',new,52+32*i,1,offset,address,r[3]+address-r[2],size,size,flags,4096)
  notes.append({'virtual':hex(address),'bytes':size,'original_file_offset':start,'sha256':sha(data)})
 header=h.copy();header[4]=entry;header[5]=52;header[10]=len(regions);header[6]=header[11]=header[12]=header[13]=0;struct.pack_into('<16sHHIIIIIHHHHHH',new,0,*header)
 path=a.output/(name+'-analysis.elf');path.write_bytes(new)
 record={'view':name,'parent_sha256':sha(raw),'view_sha256':sha(new),'view_bytes':len(new),'analyst_entry':hex(entry),'regions':notes,'native_operations':0,'limits':['Exact retained G155 code/rodata bytes and virtual addresses; analyst headers/file offsets/entry seed. Dependencies and runtime data outside listed regions omitted.','Not a replacement executable, native execution trace, live handler identity or negative proof about absent code.']}
 (a.output/(name+'-view.json')).write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record))
