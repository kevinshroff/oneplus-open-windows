"""Check original PIL's public SCM wrapper after a diagnostic-filtered result."""
from pathlib import Path
import argparse,hashlib,json,struct
import pefile
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_BLOCK
from unicorn.arm64_const import *
p=argparse.ArgumentParser();p.add_argument('--pil',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists()
raw=a.pil.read_bytes();digest=hashlib.sha256(raw).hexdigest();assert digest=='75dd928e1333044a9c7de275753e61b3c44ad5efb3051c62c3a12aa08f559716'
PIL,ARENA,STOP=0x50000000,0x30000000,0x10000000;pe=pefile.PE(data=raw);pe.relocate_image(PIL);image=pe.get_memory_mapped_image();regs=[globals()['UC_ARM64_REG_X'+str(i)]for i in range(8)]
def run(api):
 u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.mem_map(PIL,(len(image)+4095)&~4095);u.mem_write(PIL,image);u.mem_map(ARENA,0x100000);u.mem_map(STOP,4096);u.reg_write(UC_ARM64_REG_CPACR_EL1,3<<20)
 bs,ctx,cfg,state,scm=ARENA+0x10000,ARENA+0x20000,ARENA+0x21000,ARENA+0x22000,ARENA+0x30000
 q=lambda at,v:u.mem_write(at,struct.pack('<Q',v))
 q(PIL+0x1b168,bs);q(bs+0x140,ARENA+0x1000);q(ctx,cfg);q(ctx+8,state);q(scm+56,ARENA+0x1004);q(scm,0x40001)
 u.mem_write(cfg+0xec,struct.pack('<IQQ',36,0xa9f80000,0x80000));q(state,0xa9f80000);q(state+8,0x80000)
 x={'API_status_fixture':hex(api),'SCM_calls_modeled':0,'original_blocks':0}
 def ret(v=0):u.reg_write(UC_ARM64_REG_X0,v);u.reg_write(UC_ARM64_REG_PC,u.reg_read(UC_ARM64_REG_X30))
 def code(cpu,pc,n,unused):
  z=[u.reg_read(r)for r in regs]
  if pc==ARENA+0x1000:q(z[2],scm);ret();return
  if pc==ARENA+0x1004:
   assert z[:3]==[scm,0x42000202,3];args=struct.unpack('<10Q',u.mem_read(z[3],80));assert args[:3]==(36,0xa9f80000,0x80000)
   x['SCM_calls_modeled']+=1;u.mem_write(z[4],struct.pack('<4Q',1,0,0,0));ret(api);return
  if pc in [PIL+0x7b14,PIL+0x7b80,PIL+0x11cd4,PIL+0x62b4]:ret();return
  assert PIL+0x1000<=pc<PIL+0x16000,hex(pc)
 def block(cpu,pc,n,unused):
  if PIL<=pc<PIL+len(image):assert bytes(u.mem_read(pc,n))==image[pc-PIL:pc-PIL+n];x['original_blocks']+=1
 u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_BLOCK,block)
 for r,v in zip(regs,[ctx,0x2000202,3,36,0xa9f80000,0x80000,0,0]):u.reg_write(r,v)
 sp=ARENA+0xf0000;u.reg_write(UC_ARM64_REG_SP,sp);u.reg_write(UC_ARM64_REG_X30,STOP)
 saved=[globals()['UC_ARM64_REG_X'+str(i)]for i in range(19,30)];values=[0x8888000000000000+i*256 for i in range(11)]
 for r,v in zip(saved,values):u.reg_write(r,v)
 u.emu_start(PIL+0x248c,STOP,count=1000000);assert u.reg_read(UC_ARM64_REG_PC)==STOP and u.reg_read(UC_ARM64_REG_SP)==sp and[u.reg_read(r)for r in saved]==values
 x['PIL_wrapper_return']=hex(u.reg_read(UC_ARM64_REG_X0));assert int(x['PIL_wrapper_return'],16)==api and x['SCM_calls_modeled']==1,x
 return x
rows=[run(v)for v in [0,0x8000000000000007,0x8000000000000015,0x800000000000000f]]
r={'passed':True,'cases':len(rows),'PIL_sha256':digest,'original_wrapper_unchanged':True,'native_operations':0,'results':rows,'limits':['Only original PIL248c executes. SCM return/results, protocol lookup, time and logging are explicit fixtures.','Prior original range/orchestration models separately show range return7 stops before segment/auth stages with zero backup/post-image fields.']};a.output.write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r,indent=2))
