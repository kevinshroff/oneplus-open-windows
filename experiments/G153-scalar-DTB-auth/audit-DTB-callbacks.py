"""Execute the linked scalar SHA/copy/compare slice, with only final admission modeled."""
from pathlib import Path
import hashlib,json,struct
import pefile
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_MEM_READ,UC_HOOK_MEM_WRITE,UC_PROT_READ
from unicorn.arm64_const import UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X19,UC_ARM64_REG_X20,UC_ARM64_REG_X24,UC_ARM64_REG_SP,UC_ARM64_REG_PC,UC_ARM64_REG_LR
w=Path(__file__).resolve().parent;p=w/'private'
sha=lambda b:hashlib.sha256(b).hexdigest()
image=(p/'BdsDxe-linked.efi').read_bytes();pe=pefile.PE(data=image)
proof=json.loads((p/'linked-DTB-hash-REA.json').read_text());assert proof['subject']['digest']['sha256']==sha(image)
lines=proof['normalized_result']['instructions']
for suffix in ['mov w25, #0x20b8','mov w22, #0x9e980000','bl 0x0001e728','bl 0x0002234c']:
 assert any(v.endswith(suffix)for v in lines),suffix
assert not any(': blr 'in v for v in lines),'Hash callback unexpectedly uses an indirect service'
data=(w.parent/'charging-G118/private/firmware-input/firmware/image/adsp_dtb.b01').read_bytes()
expected=bytes.fromhex('f71892ad4ff2ac1100a07f63b4a5ef246749a95937a797d50480e7c70b1b2f94')
assert len(data)==8376 and hashlib.sha256(data).digest()==expected
digest_proof=json.loads((p/'linked-expected-digest-REA.json').read_text())
assert bytes.fromhex(digest_proof['normalized_result']['bytes_hex'])==expected==pe.get_data(0x65220,32)
rows=[]
for name in ['exact','corrupt','final-admission-refused']:
 u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);base=0x10000000;target=0x9e980000
 mapped=pe.get_memory_mapped_image();u.mem_map(base,(len(mapped)+4095)&~4095);u.mem_write(base,mapped)
 u.mem_map(0x90000000,0x20000);u.mem_map(target,0x3000)
 sample=bytearray(data)
 if name=='corrupt':sample[17]^=1
 u.mem_write(target,bytes(sample));u.mem_protect(target,0x3000,UC_PROT_READ)
 u.reg_write(UC_ARM64_REG_SP,0x90010000);u.reg_write(UC_ARM64_REG_X19,0x90001000)
 u.reg_write(UC_ARM64_REG_X20,1);u.reg_write(UC_ARM64_REG_X24,0x8000000000000006)
 reads=set();writes=[];calls=[];steps=[0]
 def read(uc,kind,at,n,value,opaque):
  if target<=at<target+0x3000:
   assert target<=at and at+n<=target+len(data),(hex(at),n)
   reads.update(range(at-target,at-target+n))
 def write(uc,kind,at,n,value,opaque):
  if target<=at<target+0x3000:writes.append((at,n));raise AssertionError('Target write')
 def code(uc,at,n,opaque):
  steps[0]+=1
  if at==base+0x2234c:
   assert uc.reg_read(UC_ARM64_REG_X0)==2 and uc.reg_read(UC_ARM64_REG_X1)==1
   calls.append('final-admission');uc.reg_write(UC_ARM64_REG_X0,0x800000000000000f if name=='final-admission-refused'else 0)
   uc.reg_write(UC_ARM64_REG_PC,uc.reg_read(UC_ARM64_REG_LR))
 u.hook_add(UC_HOOK_MEM_READ,read);u.hook_add(UC_HOOK_MEM_WRITE,write);u.hook_add(UC_HOOK_CODE,code)
 # Begin immediately after the successful pre-hash Check(1); stop before
 # publishing the callback return. Initial ownership/admission are not replayed.
 u.emu_start(base+0x21a70,base+0x21c24,count=1000000)
 assert u.reg_read(UC_ARM64_REG_PC)==base+0x21c24 and steps[0]<1000000
 observed=bytes(u.mem_read(base+0x74178,32));assert observed==hashlib.sha256(sample).digest()
 assert reads==set(range(len(data)))and not writes
 hashed,matched,outcome=struct.unpack('<III',u.mem_read(base+0x74024,12))
 assert hashed==1 and matched==(name!='corrupt')and outcome==(2 if name=='corrupt'else 3)
 assert calls==([]if name=='corrupt'else ['final-admission'])
 status=u.reg_read(UC_ARM64_REG_X0)
 assert status==(0x800000000000001a if name=='corrupt'else 0x800000000000000f if name=='final-admission-refused'else 0)
 rows.append({'case':name,'digest':observed.hex(),'target_bytes_read':len(reads),'target_writes':0,'instructions':steps[0],'final_admission_calls':len(calls),'status':hex(status)})
audit=json.loads((p/'image-audit.json').read_text())
result={'passed':True,'BDS_sha256':sha(image),'FD_sha256':audit['FD_sha256'],'cases':len(rows),
 'source_sha256':{n:sha((w/n).read_bytes())for n in ['OpenDtbAdmission.c','OpenSha256.h']},
 'REA_evidence_ids':[proof['evidence_id'],digest_proof['evidence_id']],
 'actual_linked_SHA_CopyMem_ZeroMem_CompareMem':True,'no_indirect_crypto_service_in_hash_callback':True,
 'native_operations':0,'results':rows,
 'limits':['The compiled slice starts after successful pre-hash admission; initial admission/ownership and final live Check(2) are not native or completely emulated here.',
 'Target data, CPU and RAM are modeled. No native physical address is accessed and no secure request executes.']}
(p/'DTB-callback-audit.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
