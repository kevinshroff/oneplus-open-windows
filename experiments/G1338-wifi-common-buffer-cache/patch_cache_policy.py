"""Bounded offline PE cache-policy patch; default inert, no signing/staging/execution."""
from pathlib import Path
import argparse,hashlib,json,struct
BASE_SHA='f59d9e98bb736ccd78aa4ebd569616456fa0f09bf345a7b1002b0105693aeeef'
RVA=0x7dbc
FILE_OFFSET=0x71bc
BEFORE=bytes.fromhex('28008052') # mov w8,#1; next instruction stores into CacheType local
AFTER=bytes.fromhex('08008052')  # mov w8,#0; same CacheType local and all its paired consumers
sha=lambda b:hashlib.sha256(b).hexdigest()
def need(ok,why):
 if not ok:raise ValueError(why)
def pe_site(b):
 need(b[:2]==b'MZ','DOS signature');pe=struct.unpack_from('<I',b,0x3c)[0];need(b[pe:pe+4]==b'PE\0\0','PE signature')
 machine,count=struct.unpack_from('<HH',b,pe+4);opt=struct.unpack_from('<H',b,pe+20)[0]
 need(machine==0xaa64 and struct.unpack_from('<H',b,pe+24)[0]==0x20b,'Exact ARM64 PE32+ required')
 rows=[]
 for i in range(count):
  s=pe+24+opt+40*i;name=b[s:s+8].rstrip(b'\0');vsize,va,rawsize,raw=struct.unpack_from('<IIII',b,s+8)
  if va<=RVA and RVA+4<=va+rawsize:rows.append((name,raw+RVA-va))
 need(rows==[(b'.text',FILE_OFFSET)],'Exact unique executable text mapping required')
 return FILE_OFFSET

def prepare(b):
 need(sha(b)==BASE_SHA,'Immutable original new-SYS SHA required')
 at=pe_site(b);need(b[at:at+4]==BEFORE,'Exact cache-policy opcode required')
 old,new=struct.unpack('<I',BEFORE)[0],struct.unpack('<I',AFTER)[0]
 need(old&0xff80001f==new&0xff80001f==0x52800008 and (old>>21)&3==0 and (new>>21)&3==0 and (old>>5)&0xffff==1 and (new>>5)&0xffff==0,'Only MOVZ w8 immediate1→0')
 result=b[:at]+AFTER+b[at+4:];diff=[i for i,(a,z)in enumerate(zip(b,result))if a!=z]
 need(len(result)==len(b) and diff==[FILE_OFFSET] and b[:at]==result[:at] and b[at+4:]==result[at+4:],'Bounded one-byte/one-instruction PE delta required')
 return result,dict(source_SYS_SHA256=BASE_SHA,candidate_SHA256=sha(result),RVA=hex(RVA),file_offset=hex(at),instruction_before=BEFORE.hex(),instruction_after=AFTER.hex(),disassembly_before='mov w8,#1',disassembly_after='mov w8,#0',changed_file_offsets=[hex(i)for i in diff],file_length=len(result),all_bytes_outside_instruction_identical=True,PE_headers_sections_imports_relocations_certificates_unchanged=True,PE_checksum_recomputed=False,scope='One cache-policy initialization; allocation CacheType and corresponding tracking metadata/error-cleanup value change together',unrelated_flags_bounds_lengths_logical_address_handling_packet_firmware_bytes_changed=False,signature_state='NOT QUALIFIED: original embedded signature invalidated; root signing and verification required separately',OEM_catalog_not_reused_as_candidate_signature_proof=True,target_calls=0,staged=False,signed=False,activated=False,runtime_approval=False)

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--prepare-offline-candidate',action='store_true');p.add_argument('--source',type=Path);p.add_argument('--output',type=Path);a=p.parse_args()
 if not a.prepare_offline_candidate:print('INERT: no input read, patch, sign, stage or execution');return
 need(a.source is not None and a.output is not None,'Explicit immutable input/new private output required');need(not a.output.exists(),'Preserve existing output; no overwrite')
 result,report=prepare(a.source.read_bytes());meta=a.output.with_suffix(a.output.suffix+'.patch.json');need(not meta.exists(),'Preserve existing patch receipt')
 with a.output.open('xb')as f:f.write(result)
 with meta.open('x')as f:json.dump(report,f,indent=2);f.write('\n')
 print(json.dumps(report,indent=2))
if __name__=='__main__':main()
