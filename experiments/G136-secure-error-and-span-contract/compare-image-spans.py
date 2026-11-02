"""Compare verified ELF load extents with G134 arguments, entirely offline."""
from pathlib import Path
import argparse,hashlib,json,struct
p=argparse.ArgumentParser();p.add_argument('--directory',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists()
expected={'adsp_dtb':'5476d25e617ebf2c51128fe1405d01f8731547ce14778a62893625dda7d0e0b1','adsp':'353c6cbb2f0f8782d3ce91818d25e195e8402d11942b8ba18ddf70f5fae2ffb8'}
rows=[]
for name,digest in expected.items():
 b=(a.directory/(name+'.mdt')).read_bytes();assert hashlib.sha256(b).hexdigest()==digest and b[:6]==b'\x7fELF\x01\x01'
 off=struct.unpack_from('<I',b,28)[0];size,count=struct.unpack_from('<HH',b,42);assert size==32 and off==52 and off+size*count<=len(b)
 selected=[]
 for i in range(count):
  kind,offset,vaddr,paddr,file_bytes,memory_bytes,flags,align=struct.unpack_from('<8I',b,off+i*size)
  if kind!=1 or not memory_bytes or(flags&0x7000000)==0x2000000:continue
  assert file_bytes<=memory_bytes and paddr+memory_bytes<=0x100000000
  selected.append({'index':i,'address':hex(paddr),'file_bytes':file_bytes,'memory_bytes':memory_bytes,'relocatable':bool(flags&0x8000000)})
 assert selected
 low=min(int(x['address'],16)for x in selected);high=max((int(x['address'],16)+x['memory_bytes']+4095)&~4095 for x in selected)
 rows.append({'image':name,'metadata_sha256':digest,'valid_load_headers':len(selected),'ELF_min':hex(low),'ELF_page_end':hex(high),'ELF_page_span':hex(high-low),'relocatable':any(x['relocatable']for x in selected),'G134_config_and_PAS_size':hex(0x80000 if name=='adsp_dtb'else 0x4880000),'last_load':selected[-1]})
assert rows[0]['ELF_page_span']=='0x3000'and rows[1]['ELF_page_span']=='0x4880000'
r={'native_operations':0,'images':rows,'observation':'The public Linux loader reference uses ELF span for MEM_SETUP. Original UEFI also uses configured0x80000 for its stock DTB profile. The difference alone does not prove a native bug or authorize changing placement.','next':'Qualify capture of exact secure X0 before selecting the next one-use native request. Retain the full reservation and main BSS extent.'}
a.output.write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r,indent=2))
