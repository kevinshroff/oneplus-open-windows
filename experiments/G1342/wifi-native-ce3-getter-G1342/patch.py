#!/usr/bin/env python3
"""Offline G1342 table-only derivative. Default inert; no signing or target calls."""
import argparse, hashlib, json, pathlib, struct
BASE='2a0d977055dd6e8e59cbad80f2e3462d6e1e2d6a62d88f18a0753504d60e8495'
OLD=(0x1b85400,0x1b85404,0x1b85408,0x1b8540c,0x1b85010,0x1b85014,0x1b8506c,0x1b85070)
NEW=OLD[:4]+(0x1b86400,0x1b86404)+OLD[6:]
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
 need(len(b)==3841536 and sha(b)==BASE,'Exact G1340 unsigned base required')
 table=pe_offset(b,0x14e184);off=pe_offset(b,0x14e194)
 need(pe_offset(b,0x14e19b)==off+7,'Contiguous patch span required')
 need(struct.unpack_from('<8I',b,table)==OLD,'Exact original allowlist required')
 c=bytearray(b);struct.pack_into('<2I',c,off,NEW[4],NEW[5]);c=bytes(c)
 need(c[:off]==b[:off] and c[off+8:]==b[off+8:] and len(c)==len(b),'Whole-image parity outside table pair required')
 need(struct.unpack_from('<8I',c,table)==NEW,'Exact new allowlist required')
 return c,off
def main():
 p=argparse.ArgumentParser();p.add_argument('--build-offline',action='store_true');p.add_argument('--base',type=pathlib.Path);p.add_argument('--out',type=pathlib.Path);a=p.parse_args()
 if not a.build_offline:print('INERT: no file read or output');return
 need(a.base is not None and a.out is not None,'Explicit base and new output directory required')
 b=a.base.read_bytes();c,off=derive(b);a.out.mkdir(parents=True,exist_ok=False)
 target=a.out/'qcwlanhmt8380-G1342-unsigned.sys';target.write_bytes(c)
 result=dict(schema='G1342-table-only-patch/1',base_unsigned_sha256=sha(b),candidate_unsigned_sha256=sha(c),candidate_bytes=len(c),patch_script_sha256=sha(pathlib.Path(__file__).read_bytes()),RVA_begin='0x14e194',RVA_end_exclusive='0x14e19c',file_offset=off,changed_offsets=[i for i,(x,y) in enumerate(zip(b,c)) if x!=y],old_registers=[hex(x) for x in OLD],new_registers=[hex(x) for x in NEW],whole_image_parity_outside_8byte_span=True,executable_instructions_unchanged=True,unwind_and_native_HAL_unchanged=True,signature_qualified=False,runtime_approved=False,target_calls=0)
 (a.out/'PATCH-MANIFEST.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
if __name__=='__main__':main()
