#!/usr/bin/env python3
"""Offline two-site G1346 power-retention experiment. Default inert; no device/signing calls."""
import argparse,hashlib,json,pathlib,struct
BASE='c5b543e6881e0e484caa8655444c6967c9864f6f64f18e2bfa319958866eaf21'
SITES=(0x1b334c,0x228548)
NOP=0xd503201f

def sha(data):return hashlib.sha256(data).hexdigest()
def need(ok,message):
 if not ok:raise ValueError(message)
def pe_offset(data,rva):
 pe=struct.unpack_from('<I',data,0x3c)[0];need(data[pe:pe+4]==b'PE\0\0','PE required');machine,count=struct.unpack_from('<HH',data,pe+4);size=struct.unpack_from('<H',data,pe+20)[0]
 need(machine==0xaa64 and struct.unpack_from('<H',data,pe+24)[0]==0x20b,'ARM64 PE32+ required')
 hits=[]
 for n in range(count):
  section=pe+24+size+40*n;vsize,va,rawsize,rawptr=struct.unpack_from('<IIII',data,section+8)
  if va<=rva<va+min(vsize,rawsize):hits.append(rawptr+rva-va)
 need(len(hits)==1,'Unique file-backed RVA required');return hits[0]
def branch_word(pc,target,link=False):
 delta=target-pc;need(delta%4==0 and -(1<<27)<=delta<(1<<27),'A64 B/BL target out of range')
 return (0x94000000 if link else 0x14000000)|((delta//4)&0x3ffffff)
def derive(data):
 need(len(data)==3841536 and sha(data)==BASE,'Exact G1344 unsigned input required')
 pc0,pc1=SITES;expected=(branch_word(pc0,0x1aa3c8,True),0x54000000|(((0x22857c-pc1)//4)<<5));new=(NOP,branch_word(pc1,0x22857c))
 out=bytearray(data);sites=[];allowed=set()
 for rva,old_word,new_word in zip(SITES,expected,new):
  offset=pe_offset(data,rva);need(pe_offset(data,rva+3)==offset+3,'Contiguous instruction required');need(struct.unpack_from('<I',data,offset)[0]==old_word,'Exact reviewed instruction required')
  struct.pack_into('<I',out,offset,new_word);allowed.update(range(offset,offset+4));sites.append(dict(rva=hex(rva),file_offset=offset,old_word=hex(old_word),new_word=hex(new_word)))
 out=bytes(out);changed=[n for n,(a,b)in enumerate(zip(data,out))if a!=b];need(changed and set(changed)<=allowed and len(out)==len(data),'Whole-image parity outside two words required')
 return out,sites,changed

def main():
 p=argparse.ArgumentParser();p.add_argument('--build-offline',action='store_true');p.add_argument('--base',type=pathlib.Path);p.add_argument('--out',type=pathlib.Path);args=p.parse_args()
 if not args.build_offline:print('INERT: no file reads or output');return
 need(args.base is not None and args.out is not None,'Explicit base and exclusive new output required');data=args.base.read_bytes();candidate,sites,changed=derive(data);args.out.mkdir(parents=True,exist_ok=False)
 (args.out/'qcwlanhmt8380-G1346-unsigned.sys').write_bytes(candidate)
 result=dict(schema='G1346-two-site-power-retention-patch/1',experiment='Per-boot dual-domain power retention; not a diagnosed fix or suspend-capable driver',base_unsigned_sha256=sha(data),candidate_unsigned_sha256=sha(candidate),candidate_bytes=len(candidate),patch_script_sha256=sha(pathlib.Path(__file__).read_bytes()),sites=sites,changed_offsets=changed,changed_bytes=len(changed),whole_image_parity_outside_two_instruction_words=True,wake_assertion_reference_arithmetic_locks_counters_unchanged=True,generic_write_helpers_unchanged=True,NC_getter_nohint_transport_unwind_other_bytes_unchanged=True,signature_qualified=False,runtime_approved=False,target_calls=0)
 (args.out/'PATCH-MANIFEST.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
if __name__=='__main__':main()
