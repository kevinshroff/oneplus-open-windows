#!/usr/bin/env python3
"""Offline G1344 optional scan-hint suppression. Default inert; no signing/device calls."""
import argparse, hashlib, json, pathlib, struct
BASE='a98840b66a8598ddb4ef2aa59300e36b4f1a6d626156b4f9aa68c1b6ec1961db'
SITES={0x1d76bc:0x248,0x1d76cc:0x260,0x1d7bfc:0x248,0x1d7c10:0x248,0x1d7c78:0x248,0x1d7c8c:0x260,0x1d7ca0:0x260,0x1d7d84:0x260}
MOV_W8_ZERO=0x52800008
def sha(b):return hashlib.sha256(b).hexdigest()
def need(v,m):
 if not v:raise ValueError(m)
def pe_offset(b,rva):
 pe=struct.unpack_from('<I',b,0x3c)[0];need(b[pe:pe+4]==b'PE\0\0','PE required');machine,n=struct.unpack_from('<HH',b,pe+4);size=struct.unpack_from('<H',b,pe+20)[0]
 need(machine==0xaa64 and struct.unpack_from('<H',b,pe+24)[0]==0x20b,'ARM64 PE32+ required')
 hits=[]
 for i in range(n):
  at=pe+24+size+i*40;vs,va,raw,off=struct.unpack_from('<IIII',b,at+8)
  if va<=rva<va+min(vs,raw):hits.append(off+rva-va)
 need(len(hits)==1,'Unique file-backed RVA required');return hits[0]
def derive(b):
 need(len(b)==3841536 and sha(b)==BASE,'Exact G1342 unsigned base required')
 c=bytearray(b); sites=[]; allowed=set()
 for rva,disp in SITES.items():
  off=pe_offset(b,rva);need(pe_offset(b,rva+3)==off+3,'Contiguous instruction required')
  expected=0xb9400000|((disp//4)<<10)|(20<<5)|8
  need(struct.unpack_from('<I',b,off)[0]==expected,'Exact LDR W8,[X20,#count] required')
  struct.pack_into('<I',c,off,MOV_W8_ZERO);allowed.update(range(off,off+4))
  sites.append(dict(rva=hex(rva),file_offset=off,old_word=hex(expected),new_word=hex(MOV_W8_ZERO),source_count_offset=hex(disp)))
 c=bytes(c);changed=[i for i,(x,y) in enumerate(zip(b,c)) if x!=y]
 need(len(c)==len(b) and set(changed)<=allowed,'Whole image parity outside eight instructions required')
 return c,sites,changed

def main():
 p=argparse.ArgumentParser();p.add_argument('--build-offline',action='store_true');p.add_argument('--base',type=pathlib.Path);p.add_argument('--out',type=pathlib.Path);a=p.parse_args()
 if not a.build_offline: print('INERT: no file read or output');return
 need(a.base is not None and a.out is not None,'Explicit base and new output directory required')
 b=a.base.read_bytes();c,sites,changed=derive(b);a.out.mkdir(parents=True,exist_ok=False)
 (a.out/'qcwlanhmt8380-G1344-unsigned.sys').write_bytes(c)
 result=dict(schema='G1344-scan-hint-suppression-patch/1',base_unsigned_sha256=sha(b),candidate_unsigned_sha256=sha(c),candidate_bytes=len(c),patch_script_sha256=sha(pathlib.Path(__file__).read_bytes()),sites=sites,changed_offsets=changed,whole_image_parity_outside_32_instruction_bytes=True,source_argument_unmodified=True,unwind_and_native_HAL_and_getter_unchanged=True,signature_qualified=False,runtime_approved=False,target_calls=0)
 (a.out/'PATCH-MANIFEST.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
if __name__=='__main__':main()
