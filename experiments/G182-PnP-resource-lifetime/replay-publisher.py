"""Replay the REA-observed compiled publication slice with explicit UEFI models."""
from pathlib import Path
import hashlib,json,struct
import pefile
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_BLOCK
from unicorn.arm64_const import *
w=Path(__file__).resolve().parent;p=w/'private';b=(p/'BdsDxe-linked.efi').read_bytes();v=json.loads((p/'REA-publisher-body.json').read_text());sha=lambda b:hashlib.sha256(b).hexdigest()
assert sha(b)==v['subject']['digest']['sha256']=='255d9d33cd46e40598c084d888d243a30520f45cefc075a66000c088421bac7b'
base,arena=0x10000000,0x90000000;pe=pefile.PE(data=b);pe.relocate_image(base);image=pe.get_memory_mapped_image();aml=(p/'verify-final/OPRES182.aml').read_bytes();assert image[0x256b0:0x256b0+376]==aml
cases=[]
for kind in ['success','already-attempted','bad-checksum','locate-error','allocation-error','install-error','debug-enabled']:
 u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.mem_map(base,(len(image)+4095)&~4095);u.mem_write(base,image);u.mem_map(arena,0x20000)
 q=lambda a,n:u.mem_write(a,struct.pack('<Q',n));R=lambda n:globals()['UC_ARM64_REG_X'+str(n)]
 bs,acpi=arena+0x1000,arena+0x2000;loc,install=arena+0x1100,arena+0x1300;copy=arena+0x4000;sp=arena+0x8000;fp=sp+0x600
 q(base+0x7b248,bs);q(bs+0x140,loc);q(acpi,install);u.mem_write(base+0x7b079,bytes([int(kind=='already-attempted')]))
 if kind=='bad-checksum':u.mem_write(base+0x256b0,b'X')
 u.reg_write(UC_ARM64_REG_SP,sp);u.reg_write(R(29),fp);u.reg_write(R(24),base+0x7b000);u.reg_write(R(28),int(kind=='debug-enabled'))
 calls=[];blocks=0;stop=[]
 def ret(n):u.reg_write(R(0),n);u.reg_write(UC_ARM64_REG_PC,u.reg_read(UC_ARM64_REG_LR))
 def code(cpu,pc,size,unused):
  if pc in [base+0x91e0,base+0x9200,base+0x91e8]:stop.append(pc);u.emu_stop();return
  if pc==loc:
   assert u.reg_read(R(0))==base+0x75990 and u.reg_read(R(1))==0 and u.reg_read(R(2))==fp-0xc8
   calls.append('locate');q(fp-0xc8,acpi);ret(0x800000000000000e if kind=='locate-error'else 0);return
  if pc==base+0xc4a8:
   assert u.reg_read(R(0))==376 and u.reg_read(R(1))==base+0x256b0;calls.append('allocate-copy');u.mem_write(copy,bytes(u.mem_read(base+0x256b0,376)));ret(0 if kind=='allocation-error'else copy);return
  if pc==install:
   assert [u.reg_read(R(i))for i in range(4)]==[acpi,copy,376,sp+0x140]and bytes(u.mem_read(copy,376))==aml
   calls.append('install');q(sp+0x140,123);ret(0x8000000000000007 if kind=='install-error'else 0);return
  if pc==base+0xc4b8:assert u.reg_read(R(0))==copy;calls.append('free');ret(0);return
  if pc==base+0x17c0:calls.append('debug');ret(0);return
  assert base+0x9198<=pc<=base+0x91dc or base+0x948c<=pc<=base+0x9504,hex(pc)
 def block(cpu,pc,size,unused):
  nonlocal_dummy=0
  if base<=pc<base+len(image):assert bytes(u.mem_read(pc,size))==image[pc-base:pc-base+size]
 u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_BLOCK,block);u.emu_start(base+0x9198,arena+0x1f000,count=10000);assert stop and bytes(u.mem_read(base+0x7b079,1))==b'\x01'
 expected=[]if kind in ['already-attempted','bad-checksum']else ['locate']if kind=='locate-error'else ['locate','allocate-copy']if kind=='allocation-error'else ['locate','allocate-copy','install','free']+(['debug']if kind=='debug-enabled'else [])
 assert calls==expected,(kind,calls);cases.append({'case':kind,'callbacks_modeled':calls,'attempt_latched':True})
r={'passed':True,'cases':len(cases),'BDS_sha256':sha(b),'REA_evidence_id':v['evidence_id'],'entry_RVA':'0x9198','native_operations':0,'results':cases,'limits':['Actual compiled AArch64 checksum/attempt guard/publication flow; executed basic blocks compare to the pinned image.','UEFI protocol lookup,allocation,installation,free and debug are explicit modeled callbacks. This does not qualify native ACPI enumeration or OS resources.']};(p/'publisher-replay.json').write_text(json.dumps(r,indent=2)+'\n');print({k:v for k,v in r.items()if k!='results'})
