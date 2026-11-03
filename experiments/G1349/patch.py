#!/usr/bin/env python3
"""Offline G1349 scan-priority discriminator. No signing, host or device access."""
import argparse, hashlib, json, pathlib, struct
BASE='cb2ddd7e233f7c1af26ae2ef508fd7f72d6fc11744761a7ad5c61304add9988e'
SITE=0x1d775c
CAVE=0x1d7c24
RETURN=0x1d7760
BODY=bytes.fromhex('890300522911c05a297d05538903090b69220229')
OLD_CAVE=bytes.fromhex('d50700b091420991282640a984431891a3421a91020080d2')
GUARDS={0x1d775c:'7c220229',0x1d7c10:'08008052a8030034',0x1d7c78:'08008052',0x1d7c8c:'08008052',0x1d7ca0:'08008052',0x7dbc:'08008052',0x1b334c:'1f2003d5',0x228548:'0d000014'}
def sha(data):return hashlib.sha256(data).hexdigest()
def need(ok,message):
 if not ok:raise ValueError(message)
def pe_offset(data,rva):
 pe=struct.unpack_from('<I',data,0x3c)[0];need(data[pe:pe+4]==b'PE\0\0','PE required')
 machine,count=struct.unpack_from('<HH',data,pe+4);optional=struct.unpack_from('<H',data,pe+20)[0]
 need(machine==0xaa64 and struct.unpack_from('<H',data,pe+24)[0]==0x20b,'ARM64 PE32+ required')
 hits=[]
 for i in range(count):
  s=pe+24+optional+i*40;vs,va,rs,rp=struct.unpack_from('<IIII',data,s+8)
  if va<=rva<va+min(vs,rs):hits.append(rp+rva-va)
 need(len(hits)==1,'Unique file-backed RVA required');return hits[0]
def branch(pc,target):
 delta=target-pc;need(delta%4==0 and -(1<<27)<=delta<(1<<27),'B range/alignment')
 return struct.pack('<I',0x14000000|((delta//4)&0x3ffffff))
def branch_target(pc,word):
 need(word>>26==5,'Unconditional B required');imm=word&0x3ffffff
 if imm&(1<<25):imm-=1<<26
 return pc+4*imm
def derive(data):
 need(len(data)==3841536 and sha(data)==BASE,'Exact unsigned G1346 input required')
 for rva,old in GUARDS.items():
  off=pe_offset(data,rva);need(data[off:off+len(bytes.fromhex(old))]==bytes.fromhex(old),'Guard at '+hex(rva))
 off=pe_offset(data,CAVE);need(data[off:off+24]==OLD_CAVE,'Exact unreachable hint-loop cave required')
 patches={SITE:branch(SITE,CAVE),CAVE:BODY+branch(CAVE+len(BODY),RETURN)}
 out=bytearray(data);allowed=set();sites=[]
 for rva,new in patches.items():
  off=pe_offset(data,rva);need(pe_offset(data,rva+len(new)-1)==off+len(new)-1,'File continuity')
  sites.append({'rva':hex(rva),'file_offset':off,'before_hex':data[off:off+len(new)].hex(),'after_hex':new.hex()})
  out[off:off+len(new)]=new;allowed.update(range(off,off+len(new)))
 out=bytes(out);changed=[i for i,(a,b) in enumerate(zip(data,out)) if a!=b]
 need(changed and set(changed)<=allowed and len(out)==len(data),'Bounded whole-file diff')
 need(branch_target(SITE,struct.unpack('<I',patches[SITE])[0])==CAVE,'Entry branch')
 need(branch_target(CAVE+20,struct.unpack('<I',patches[CAVE][-4:])[0])==RETURN,'Return branch')
 return out,sites,changed

def main():
 p=argparse.ArgumentParser();p.add_argument('--build-offline',action='store_true');p.add_argument('--base',type=pathlib.Path);p.add_argument('--out',type=pathlib.Path);a=p.parse_args()
 if not a.build_offline:print('INERT: no file reads or output');return
 need(a.base is not None and a.out is not None,'Explicit base and exclusive output required')
 data=a.base.read_bytes();out,sites,changed=derive(data);a.out.mkdir(parents=True,exist_ok=False)
 (a.out/'qcwlanhmt8380-G1349-unsigned.sys').write_bytes(out)
 result={'schema':'G1349-priority-only-patch/1','base_unsigned_sha256':sha(data),'candidate_unsigned_sha256':sha(out),'candidate_bytes':len(out),'patch_script_sha256':sha(pathlib.Path(__file__).read_bytes()),'sites':sites,'changed_offsets':changed,'changed_bytes':len(changed),'priority_mapping':'1 -> 2; all other u32 values unchanged','whole_image_parity_outside_two_spans':True,'baseline_nohint_required':True,'NC_getter_nohint_wake_unwind_other_bytes_unchanged':True,'compiled_review_passed':False,'signing_qualified':False,'runtime_approved':False,'target_calls':0}
 (a.out/'PATCH-MANIFEST.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
if __name__=='__main__':main()
