#!/usr/bin/env python3
"""Exact-byte REA views; no target execution or native state change."""
import argparse,hashlib,json,pathlib,struct
p=argparse.ArgumentParser();p.add_argument('--input',type=pathlib.Path,required=True);p.add_argument('--output',type=pathlib.Path,required=True);a=p.parse_args()
b=a.input.read_bytes();sha=lambda v:hashlib.sha256(v).hexdigest();assert sha(b)=='96dec3f35f9bd2fff7edce48d280d0cefc16e1029f969df8b8a9a41f8c3b5507'
h=list(struct.unpack_from('<16sHHIIIIIHHHHHH',b));rows=[struct.unpack_from('<8I',b,h[5]+32*i)for i in range(h[10])]
spec={
 'Power4':(0x60050000,[(0x60050000,0x10000,5),(0x60220000,0x80000,4),(0x602a3000,0xa80c,6)]),
 'Router':(0x601c26e0,[(0x601c0000,0x10000,5),(0x6002c000,0x3000,5),(0x60270000,0x30000,4),(0x602a3000,0xa80c,6)]),
 'ChgCtor-candidate':(0x60171e70,[(0x60170000,0x6000,5),(0x60260000,0x20000,4)]),
 'ChgInit':(0x601720a0,[(0x60170000,0x6000,5),(0x60260000,0x20000,4)]),
 'ChgFvCallback':(0x60172500,[(0x60170000,0x6000,5),(0x60260000,0x20000,4)]),
 'RegisterAccess':(0x601b3820,[(0x601b0000,0x10000,5),(0x6002c000,0x3000,5),(0x60270000,0x30000,4),(0x602a3000,0xa80c,6)]),
 'BattLibrary':(0x60171e70,[(0x60000000,0x2a2c84,5,0x2a3000),(0x602a3000,0xa80c,6,0x108000)]),
 'DivideHelper':(0x60009a20,[(0x60009000,0x3000,5)]),
}
a.output.mkdir(parents=True,exist_ok=False)
for name,(entry,regions)in spec.items():
 out=bytearray(4096);notes=[]
 for i,region in enumerate(regions):
  addr,n,flags=region[:3];memsz=region[3]if len(region)==4 else n
  match=[r for r in rows if r[2]<=addr and addr+n<=r[2]+r[4]];assert len(match)==1;r=match[0];at=r[1]+addr-r[2];data=b[at:at+n]
  if name=='BattLibrary':out.extend(bytes((-len(out))%4096))
  off=len(out);out.extend(data)
  struct.pack_into('<8I',out,52+32*i,1,off,addr,r[3]+addr-r[2],n,memsz,flags,4096)
  notes.append({'virtual':hex(addr),'bytes':n,'parent_file_offset':at,'sha256':sha(data)})
 header=h.copy();header[4]=entry;header[5]=52;header[10]=len(regions);header[6]=header[11]=header[12]=header[13]=0;struct.pack_into('<16sHHIIIIIHHHHHH',out,0,*header)
 if name=='BattLibrary':out.extend(bytes((-len(out))%4096))
 path=a.output/(name+'.elf');path.write_bytes(out);meta={'parent_sha256':sha(b),'view_sha256':sha(out),'entry_seed':hex(entry),'regions':notes,'limits':['Analysis-only ELF header/entry seed and file offsets. Exact original code/data bytes retained.','Omitted code, BSS and live heap are not evidence of absent behavior or actual runtime handler selection.']};(a.output/(name+'.json')).write_text(json.dumps(meta,indent=2)+'\n');print({'view':name,'bytes':len(out),'sha256':sha(out)})
