"""Execute original donor ISR/backend code with modeled helper boundaries.

No hardware or native-driver qualification. Observe offsets and calls exactly;
do not assign undocumented register names to the 0x620 accesses.
"""
from pathlib import Path
import argparse,hashlib,json,struct
import pefile
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_MEM_WRITE,UC_HOOK_MEM_READ
from unicorn.arm64_const import *
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--driver',required=True,type=Path);p.add_argument('--output',required=True,type=Path)
a=p.parse_args();assert not a.output.exists();raw=a.driver.read_bytes();sha=hashlib.sha256(raw).hexdigest();assert sha=='34cabf2e7b59d3f8c0608da80dfdc705173c82427611312d32e7c1a9720e33ec'
BASE=0x140000000;ARENA=0x30000000;CTX=ARENA+0x1000;DEV=ARENA+0x2000;ARG=ARENA+0x3000;BD=ARENA+0x4000;REGS=ARENA+0x5000;STACK=ARENA+0x3f000;MMIO=0x50000000;END=0x180000000

def run(name,backend=True,offset=0,status=0x12345678,work=True,queued=True):
 u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);image=pefile.PE(data=raw).get_memory_mapped_image();u.mem_map(BASE,(len(image)+4095)&~4095);u.mem_write(BASE,image);u.mem_map(ARENA,0x40000);u.mem_map(MMIO,0x2000);u.mem_map(END,4096)
 def w64(at,v):u.mem_write(at,struct.pack('<Q',v))
 w64(BASE+0x21048,BASE+0x21048) # WPP disabled, as observed in original control flow.
 w64(CTX+0x18,MMIO);w64(CTX+0x78,ARG);w64(CTX+0x80,1 if work else 0)
 w64(ARG,BD);w64(BD+8,REGS if backend else 0);w64(REGS,MMIO);u.mem_write(REGS+8,struct.pack('<I',offset));u.mem_write(MMIO+0x610,struct.pack('<I',status))
 regs=[UC_ARM64_REG_X19,UC_ARM64_REG_X20,UC_ARM64_REG_X21,UC_ARM64_REG_X22,UC_ARM64_REG_X23,UC_ARM64_REG_X24,UC_ARM64_REG_X25,UC_ARM64_REG_X26,UC_ARM64_REG_X27,UC_ARM64_REG_X28,UC_ARM64_REG_X29]
 for i,r in enumerate(regs):u.reg_write(r,0x88000000+i*256)
 before=[u.reg_read(r)for r in regs];u.reg_write(UC_ARM64_REG_SP,STACK);u.reg_write(UC_ARM64_REG_LR,END);u.reg_write(UC_ARM64_REG_X0,0x60000000);u.reg_write(UC_ARM64_REG_X1,0)
 writes=[];reads=[];calls=[]
 def code(uc,pc,size,data):
  functions={BASE+0x3480:('interrupt_to_device_helper',DEV),BASE+0x3c88:('device_context',CTX),BASE+0x3370:('optional_callback_helper',int(queued))}
  if pc in functions:
   name,result=functions[pc];calls.append(name);uc.reg_write(UC_ARM64_REG_X0,result);uc.reg_write(UC_ARM64_REG_PC,uc.reg_read(UC_ARM64_REG_LR))
 def write(uc,access,addr,size,value,data):
  if MMIO<=addr<MMIO+0x2000:writes.append(dict(offset=hex(addr-MMIO),bytes=size,value=hex(value)))
 def read(uc,access,addr,size,value,data):
  if MMIO<=addr<MMIO+0x2000:reads.append(dict(offset=hex(addr-MMIO),bytes=size))
 u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,write);u.hook_add(UC_HOOK_MEM_READ,read)
 u.emu_start(BASE+0xc000,END,count=200000)
 assert u.reg_read(UC_ARM64_REG_PC)==END and u.reg_read(UC_ARM64_REG_SP)==STACK
 assert before==[u.reg_read(r)for r in regs]and u.reg_read(UC_ARM64_REG_X0)==1
 expected=[dict(offset=hex(offset+0x620),bytes=4,value='0xffc0007f')]if backend else[dict(offset='0x620',bytes=4,value=hex(status&0xffc07fff))]
 assert writes==expected,(name,writes,expected)
 assert reads==([]if backend else[dict(offset='0x610',bytes=4)])
 assert ('optional_callback_helper'in calls)==(backend and work)
 return dict(name=name,backend_descriptor=backend,backend_offset=hex(offset),status_input=hex(status),writes=writes,reads=reads,calls=calls,returns_IRQ_claimed=True,SP_and_callee_saved_preserved=True)

cases=[run('normal'),run('normal_no_work',work=False),run('normal_queue_false',queued=False),run('backend_offset_propagates',offset=0x100),run('fallback_status_zero',backend=False,status=0),run('fallback_status_mask',backend=False,status=0xffffffff),run('fallback_mixed',backend=False,status=0xa5a5a5a5)]
r=dict(driver_sha256=sha,original_functions=['0x14000c000','0x140013b38','0x140017a08'],modeled_API_boundaries=['helper@0x140003480 (modeled device handle)','device_context@0x140003c88','helper@0x140003370 (modeled callback result)'],passed=len(cases),cases=cases,observations=['The normal backend writes constant0xffc0007f to backend_base+backend_offset+0x620 before the optional callback-helper call.','With absent backend register descriptor, the fallback reads context_MMIO+0x610 and writes status&0xffc07fff to context_MMIO+0x620.','These observed paths do not access offset0x618 and return claimed=1, including zero-status fallback.'],limitations=['Local original ARM64 execution only; modeled helper return values and memory registers; exact framework API identities are not established here.','Backend offset is a runtime field; actual native value and register0x620 semantics remain unqualified.','This does not demonstrate hardware compatibility, valid IRQ acknowledgement, DMA, transfer or native SPI operation.'])
a.output.write_text(json.dumps(r,indent=2)+'\n');print('Original SPI ISR/backend cases passed',len(cases))
