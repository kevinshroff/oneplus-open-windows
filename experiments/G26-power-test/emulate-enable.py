"""Run the original AOP enable function with modeled SPMI API boundaries.

This validates register/byte/ABI behavior, not voltage, the bus or live firmware.
"""
from pathlib import Path
import argparse,hashlib,importlib.util,json,struct
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_THUMB,UC_MODE_MCLASS,UC_HOOK_CODE
from unicorn.arm_const import *
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--image',required=True,type=Path);p.add_argument('--output',required=True,type=Path)
p.add_argument('--aop-decoder',required=True,type=Path)
a=p.parse_args();assert not a.output.exists()
W=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('aop_decode',a.aop_decoder);mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
elf=mod.Elf(a.image,mod.AOP_SHA)
ARENA,CTX,COMM,PERIPH,STACK,END=0x30000000,0x30001000,0x30002000,0x30003000,0x3003f000,0x10000000

def case(name,enabled,index=3,present=True,full=True,old=0,hw_error=False,initialized=True):
 u=Uc(UC_ARCH_ARM,UC_MODE_THUMB|UC_MODE_MCLASS);pages=set();segs=[]
 for s in elf.segments:
  va=s['va']-0xb000000 if s['va']in[0xb000000,0xb0e0000]else s['va'];segs.append((s,va));pages.update(range(va&~4095,(va+s['memsz']+4095)&~4095,4096))
 for page in sorted(pages):u.mem_map(page,4096)
 for s,va in segs:u.mem_write(va,elf.raw[s['offset']:s['offset']+s['filesz']])
 u.mem_map(ARENA,0x40000);u.mem_map(END,4096)
 def w32(at,x):u.mem_write(at,struct.pack('<I',x))
 def r32(at):return struct.unpack('<I',u.mem_read(at,4))[0]
 for literal in [0xde38,0xdebc]:u.mem_write(r32(literal),bytes([int(initialized)]))
 w32(CTX+4,0xe138c);w32(CTX+8,17);w32(CTX+12,PERIPH);w32(COMM,1)
 u.mem_write(PERIPH+3*28+12,struct.pack('<H',0xc400));u.mem_write(PERIPH+3*28+14,bytes([4 if present else 0]));u.mem_write(PERIPH+3*28+16,bytes([int(full)]))
 saved_regs=[UC_ARM_REG_R4,UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_R7,UC_ARM_REG_R8,UC_ARM_REG_R9,UC_ARM_REG_R10,UC_ARM_REG_R11]
 for i,r in enumerate(saved_regs):u.reg_write(r,0x88000000+i*256)
 saved=[u.reg_read(r)for r in saved_regs]
 u.reg_write(UC_ARM_REG_SP,STACK);u.reg_write(UC_ARM_REG_LR,END|1)
 for r,x in [(UC_ARM_REG_R0,CTX),(UC_ARM_REG_R1,COMM),(UC_ARM_REG_R2,index),(UC_ARM_REG_R3,enabled)]:u.reg_write(r,x)
 calls=[]
 def hook(uc,pc,size,data):
  if pc not in [0xe828,0xe6a0]:return
  sp=uc.reg_read(UC_ARM_REG_SP);bus=uc.reg_read(UC_ARM_REG_R0);sid=uc.reg_read(UC_ARM_REG_R1);addr=uc.reg_read(UC_ARM_REG_R3);buffer=r32(sp);length=r32(sp+4)
  assert bus==0 and sid==1 and addr==0xc446 and length==1
  if pc==0xe6a0:
   uc.mem_write(buffer,bytes([old]));w32(r32(sp+8),1);calls.append(dict(kind='read',sid=sid,address=hex(addr),bytes=[old]))
  else:calls.append(dict(kind='write',sid=sid,address=hex(addr),bytes=list(uc.mem_read(buffer,length))))
  uc.reg_write(UC_ARM_REG_R0,int(hw_error));uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
 u.hook_add(UC_HOOK_CODE,hook)
 u.emu_start(0xe0f1,END,count=200000)
 assert u.reg_read(UC_ARM_REG_PC)==END and u.reg_read(UC_ARM_REG_SP)==STACK
 assert[u.reg_read(r)for r in saved_regs]==saved
 result=u.reg_read(UC_ARM_REG_R0)
 expected=0x40 if index>=17 or not present else 4 if enabled>1 else 0x80 if not initialized or hw_error else 0
 assert result==expected,(name,result,expected)
 writes=[c for c in calls if c['kind']=='write']
 if expected in [4,0x40]or not initialized:assert not calls
 else:assert len(writes)==1 and writes[0]['bytes']==[((0x80 if enabled else 0) | (old&0x7f if not full else 0))]
 return dict(name=name,status=hex(result),SP_and_callee_saved_preserved=True,calls=calls)

cases=[case('enable',1),case('disable',0),case('invalid_enable',2),case('out_of_range',1,index=17),case('missing_peripheral',1,present=False),case('write_error',1,hw_error=True),case('uninitialized',1,initialized=False),case('masked_preserve_bits',1,full=False,old=0x20)]
r=dict(image_sha256=elf.sha,original_function='0xe0f0',cases=cases,passed=len(cases),modeled_hardware_API_boundaries=['SpmiBus_ReadLong@0xe6a0','SpmiBus_WriteLong@0xe828'],limitations=['Local CPU/memory behavior only; hardware APIs are modeled.','Original enable/PMIC wrappers and register table bytes execute unchanged.'])
a.output.write_text(json.dumps(r,indent=2)+'\n');print('Original AOP enable cases passed',len(cases))
