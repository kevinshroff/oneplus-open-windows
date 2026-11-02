"""Seed the observed 600d8580 prologue near the SCHG initialization log site.

An immutable focused ELF, not native firmware. Reachability and unmodeled
callees remain explicit; no handler-selection conclusion follows from a seed.
"""
from pathlib import Path
import argparse,hashlib,json,struct
p=argparse.ArgumentParser();p.add_argument('--input',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--symbols',action='store_true');a=p.parse_args()
b=a.input.read_bytes();sha=lambda v:hashlib.sha256(v).hexdigest();assert sha(b)=='96dec3f35f9bd2fff7edce48d280d0cefc16e1029f969df8b8a9a41f8c3b5507'
h=list(struct.unpack_from('<16sHHIIIIIHHHHHH',b));rows=[struct.unpack_from('<8I',b,h[5]+32*i)for i in range(h[10])]
spec=[(0x600d0000,0x10000,5,0x10000),(0x60240000,0x20000,4,0x20000),(0x602a3000,0xa80c,6,0x108000),(0x603d0000,0x10000,4,0x10000)]
a.output.mkdir(parents=True,exist_ok=False);out=bytearray(4096);notes=[]
for i,(addr,n,flags,memsz)in enumerate(spec):
 match=[r for r in rows if r[2]<=addr and addr+n<=r[2]+r[4]];assert len(match)==1
 r=match[0];start=r[1]+addr-r[2];raw=b[start:start+n];out.extend(bytes((-len(out))%4096));off=len(out);out.extend(raw)
 struct.pack_into('<8I',out,52+32*i,1,off,addr,r[3]+addr-r[2],n,memsz,flags,4096)
 notes.append({'virtual':hex(addr),'physical':hex(r[3]+addr-r[2]),'parent_file_offset':start,'view_file_offset':off,'file_bytes':n,'memory_bytes':memsz,'sha256':sha(raw)})
h[4]=0x600d8580;h[5]=52;h[10]=len(spec);h[6]=h[11]=h[12]=h[13]=0
symbols={}
if a.symbols:
 # Explicit analyst entry seeds let the loader define functions that its
 # automatic sweep missed. No instruction or loaded data byte changes.
 symbols={0x600d6250:'candidate_model47_enable',0x600d6960:'candidate_model47_status_R2',0x600d8580:'observed_schg_initializer',0x600d8f00:'candidate_scpq2_initializer'}
 strings=bytearray(b'\0');syms=bytearray(16)
 for addr,name in symbols.items():
  at=len(strings);strings.extend(name.encode()+b'\0');syms.extend(struct.pack('<IIIBBH',at,addr,0,0x12,0,1))
 string_off=len(out);out.extend(strings);out.extend(bytes((-len(out))%4));sym_off=len(out);out.extend(syms)
 shnames=b'\0.text\0.strtab\0.symtab\0.shstrtab\0';shnames_off=len(out);out.extend(shnames);out.extend(bytes((-len(out))%4));shoff=len(out)
 shdrs=[(0,0,0,0,0,0,0,0,0,0),(1,1,6,0x600d0000,notes[0]['view_file_offset'],0x10000,0,0,4,0),(7,3,0,0,string_off,len(strings),0,0,1,0),(15,2,0,0,sym_off,len(syms),2,1,4,16),(23,3,0,0,shnames_off,len(shnames),0,0,1,0)]
 for row in shdrs:out.extend(struct.pack('<10I',*row))
 h[6]=shoff;h[11]=40;h[12]=len(shdrs);h[13]=4
struct.pack_into('<16sHHIIIIIHHHHHH',out,0,*h)
for row in notes:assert sha(out[row['view_file_offset']:row['view_file_offset']+row['file_bytes']])==row['sha256']
(a.output/'PmicInit.elf').write_bytes(out);proof={'parent_sha256':sha(b),'view_sha256':sha(out),'entry_seed':'0x600d8580','analyst_symbol_seeds':{hex(k):v for k,v in symbols.items()},'seed_basis':'REA masked byte search matches known allocframe encoding; nearest candidate before QSR model-error site600d8a10. Original view did not decode it; new seed must validate instructions and identity.','regions':notes,'all_loaded_bytes_equal_original':True,'native_operations':0,'limits':['Headers/entry/file offsets/symbol seeds are analyst choices. Other code/protection domains and live BSS omitted.','A function seed does not prove the runtime initializer or selected model.']};(a.output/'proof.json').write_text(json.dumps(proof,indent=2)+'\n');print({'view_sha256':sha(out),'bytes':len(out),'native_operations':0})
