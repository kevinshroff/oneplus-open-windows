"""Execute the original public custom-config request, registry and orchestration.

The six ELF/PAS lifecycle callbacks are explicit return fixtures. The original
parser, record override, retail/registry checks and request recursion execute.
No native operation or full original ELF/PAS execution is claimed here.
"""
from pathlib import Path
import argparse,hashlib,json,struct
import pefile
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_BLOCK
from unicorn.arm64_const import *
p=argparse.ArgumentParser(description=__doc__)
for n in ['image','config','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();assert not a.output.exists()
sha=lambda b:hashlib.sha256(b).hexdigest()
raw=a.image.read_bytes();cfg_bytes=a.config.read_bytes()
assert sha(raw)=='75dd928e1333044a9c7de275753e61b3c44ad5efb3051c62c3a12aa08f559716'
assert sha(cfg_bytes)=='7308b7ba08813cd6f693742ba1ce8a48cd5e80bcc000d045eb774837e47c0645'
PIL,ARENA,STOP=0x50000000,0x30000000,0x10000000
pe=pefile.PE(data=raw);original=pe.get_memory_mapped_image();pe.relocate_image(PIL);image=pe.get_memory_mapped_image()
regs=[globals()['UC_ARM64_REG_X'+str(i)]for i in range(8)]
steps=[0x3144,0x265c,0x2768,0x3478,0x373c,0x3854]
def run(fail=None,clear=True):
 u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.mem_map(PIL,(len(image)+4095)&~4095);u.mem_write(PIL,image)
 u.mem_map(ARENA,0x1000000);u.mem_map(STOP,4096);u.reg_write(UC_ARM64_REG_CPACR_EL1,3<<20)
 bs=ARENA+0x10000;u.mem_write(ARENA+0x20000,cfg_bytes+b'\0');heap=ARENA+0x40000
 q=lambda at,v:u.mem_write(at,struct.pack('<Q',v))
 rq=lambda at:struct.unpack('<Q',u.mem_read(at,8))[0]
 rd=lambda at:struct.unpack('<I',u.mem_read(at,4))[0]
 q(PIL+0x1b168,bs);q(bs+0x148,ARENA+0xf00000)
 events=[];overrides=[];blocks=0;phase='init'
 def wide(at):
  b=bytes(u.mem_read(at,128));return b[:next(i for i in range(0,len(b),2)if b[i:i+2]==b'\0\0')].decode('utf-16le')
 def ret(v=0):u.reg_write(UC_ARM64_REG_X0,v);u.reg_write(UC_ARM64_REG_PC,u.reg_read(UC_ARM64_REG_X30))
 def hook(cpu,pc,n,unused):
  nonlocal heap
  z=[u.reg_read(r)for r in regs]
  if pc==PIL+0x4cc8:ret();return
  if pc==PIL+0x71ec:q(z[1],ARENA+0x20000);q(z[2],len(cfg_bytes));ret();return
  if pc==PIL+0x79ec:
   assert 0<z[0]<0x10000;v=heap;heap=(heap+z[0]+31)&~31;assert heap<ARENA+0xc00000;ret(v);return
  if pc in [ARENA+0xf00000,PIL+0x7b14,PIL+0x7b80,PIL+0x11cd4,PIL+0x62b4]:ret();return
  if pc in [PIL+0x7c7c,PIL+0x4bfc,PIL+0x10d8]:raise AssertionError(('original assertion',hex(pc),events))
  if pc==PIL+0x1c2c:
   assert phase!='init','AUTO was not empty'
  if pc==PIL+0x3d00:
   b=bytes(u.mem_read(z[0],568));name=wide(z[0]+12).upper()
   assert name in ['FULL_ADSP_DTB','FULL_ADSP'];base=0xa9f80000 if name.endswith('DTB')else 0xaa000000
   assert rq(z[0]+0xf0)==base and b[0x102]==1
   assert not any(b[0x114:0x174])and not any(b[0x1b4:0x1f4])
   overrides.append({'name':name,'global_record_sha256':sha(b),'base':hex(base)})
  if pc==PIL+0x6964:
   assert z[0]==z[1]==0 and wide(z[2])=='adsp_ro';ret();return
  if pc-PIL in steps:
   cfg=rq(z[0]);state=rq(z[0]+8);name=wide(cfg+12).upper();step=steps.index(pc-PIL)
   assert name in ['FULL_ADSP_DTB','FULL_ADSP']
   events.append({'image':name,'stage_fixture':step,'function_RVA':hex(pc-PIL)})
   if step==2:q(state,rq(cfg+0xf0));q(state+8,rq(cfg+0xf8))
   ret(7 if fail==(name,step)else 0);return
  assert PIL+0x1000<=pc<PIL+0x16000,hex(pc)
 def block(cpu,pc,n,unused):
  nonlocal blocks
  if PIL<=pc<PIL+len(original):assert bytes(u.mem_read(pc,n))==original[pc-PIL:pc-PIL+n];blocks+=1
 boundaries=[0x4cc8,0x71ec,0x79ec,0x7b14,0x7b80,0x11cd4,0x62b4,0x7c7c,0x4bfc,0x10d8,0x1c2c,0x3d00,0x6964,*steps]
 for rva in boundaries:u.hook_add(UC_HOOK_CODE,hook,begin=PIL+rva,end=PIL+rva)
 u.hook_add(UC_HOOK_CODE,hook,begin=ARENA+0xf00000,end=ARENA+0xf00000)
 u.hook_add(UC_HOOK_BLOCK,block)
 def call(rva,args=()):
  for reg,v in zip(regs,list(args)+[0]*(8-len(args))):u.reg_write(reg,v)
  sp=ARENA+0xff0000;u.reg_write(UC_ARM64_REG_SP,sp);u.reg_write(UC_ARM64_REG_X30,STOP)
  saved=[globals()['UC_ARM64_REG_X'+str(i)]for i in range(19,30)];canaries=[0x8877000000000000+i*256 for i in range(11)]
  for reg,v in zip(saved,canaries):u.reg_write(reg,v)
  u.emu_start(PIL+rva,STOP,count=4000000)
  assert u.reg_read(UC_ARM64_REG_PC)==STOP and u.reg_read(UC_ARM64_REG_SP)==sp
  assert [u.reg_read(reg)for reg in saved]==canaries
  return u.reg_read(UC_ARM64_REG_X0)
 assert call(0x1588)==0
 phase='request';records=[]
 for i,name in enumerate(['FULL_ADSP_DTB','FULL_ADSP']):
  name_at=ARENA+0x9000;cfg_at=ARENA+0x1000+i*0x1000
  u.mem_write(name_at,name.encode('utf-16le')+b'\0\0');assert call(0x17e8,[name_at,cfg_at])==0
  q(cfg_at+0xf0,0xa9f80000 if i==0 else 0xaa000000)
  if i==0:u.mem_write(cfg_at+0x102,b'\x01')
  elif clear:u.mem_write(cfg_at+0x174,bytes(64))
  result=call(0x172c,[cfg_at]);records.append({'image':name,'public_status':hex(result)})
  if result:break
 success=fail is None and clear
 assert (records[-1]['public_status']=='0x0')==success
 if success:assert len(events)==12 and len(overrides)==2 and [e['stage_fixture']for e in events]==list(range(6))*2
 elif fail is not None:
  index=0 if fail[0].endswith('DTB')else 1
  assert len(events)==index*6+fail[1]+1 and len(overrides)==index+1
 else:assert len(events)==6 and len(overrides)==2 and len(records)==2,(events,overrides,records)
 return {'failure_fixture':fail,'clear_main_preimage':clear,'original_blocks':blocks,'public_returns':records,'record_overrides':overrides,'lifecycle_return_fixtures':events}
rows=[run(),run(clear=False)]+[run((name,stage))for name in ['FULL_ADSP_DTB','FULL_ADSP']for stage in range(6)]
result={'passed':True,'cases':len(rows),'PILDxe_sha256':sha(raw),'config_sha256':sha(cfg_bytes),'native_operations':0,'observations':['The public method is table+0x10 and accepts only the config pointer, without This.','Original orchestration copies the supplied record into the existing retail entry.','Clearing main PreImage prevents a duplicate DTB request that returns already-loaded9 and aborts the request.','With zero backup/post-image fields, injected stage failures do not trigger another load.'],'models':['UEFI install, platform/config read, allocation/free, logging/time','Mount boundary for adsp_ro','Six ELF/PAS lifecycle return values; the actual metadata/header/segment paths are qualified separately.'],'limits':['No full original ELF/SCM run, native DSP request, secure success, DMA ownership or charger result is established.'],'results':rows}
a.output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:result[k]for k in ['passed','cases','native_operations','observations']},indent=2))
