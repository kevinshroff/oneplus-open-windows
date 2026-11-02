"""Run original G17 ARM64 RPMh HAL code with modeled MMIO and logging only.

The code/guard/idle/response functions execute unchanged. This does not prove
native permissions, transport response semantics or an electrical supply state.
"""
from pathlib import Path
import argparse,hashlib,json,struct
import pefile
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_MEM_READ,UC_HOOK_MEM_WRITE
from unicorn.arm64_const import *
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--image',required=True,type=Path)
p.add_argument('--output',required=True,type=Path);a=p.parse_args();assert not a.output.exists()
raw=a.image.read_bytes();sha=hashlib.sha256(raw).hexdigest()
assert sha=='8c5db67f68da5d3ddc168218c3c63515e2bedc1505e3cb62833f11fe514b3343'
pe=pefile.PE(data=raw);assert pe.FILE_HEADER.Machine==0xaa64 and pe.OPTIONAL_HEADER.ImageBase==0
mapped=pe.get_memory_mapped_image()
ARENA,STACK,END,MMIO,CTX=0x30000000,0x3003fff0,0x10000000,0x17a00000,0xe5f8
saved_regs=[UC_ARM64_REG_X19,UC_ARM64_REG_X20,UC_ARM64_REG_X21,UC_ARM64_REG_X22,UC_ARM64_REG_X23,UC_ARM64_REG_X24,UC_ARM64_REG_X25,UC_ARM64_REG_X26,UC_ARM64_REG_X27,UC_ARM64_REG_X28,UC_ARM64_REG_X29]
args_regs=[UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3]
def setup():
    u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.mem_map(0,(len(mapped)+4095)&~4095);u.mem_write(0,mapped)
    u.mem_map(ARENA,0x40000);u.mem_map(END,4096);u.mem_map(MMIO,0x40000)
    u.mem_write(CTX,b'\x01');u.mem_write(CTX+0x14,b'\x01')
    u.mem_write(CTX+0xc,struct.pack('<II',MMIO,2));u.mem_write(CTX+0x18,struct.pack('<II',8,16))
    u.reg_write(UC_ARM64_REG_SP,STACK);u.reg_write(UC_ARM64_REG_LR,END)
    for i,r in enumerate(saved_regs):u.reg_write(r,0x8800000000000000+i*256)
    events=[];logs=[]
    def mem(uc,access,address,size,value,user):
        if MMIO<=address<MMIO+0x40000:
            assert size==4
            events.append({'kind':'write'if access==17else'read','address':hex(address),'value':value if access==17else struct.unpack('<I',uc.mem_read(address,4))[0]})
    # UC_MEM_WRITE is 17; preserve explicit assertion instead of hiding hooks.
    u.hook_add(UC_HOOK_MEM_READ|UC_HOOK_MEM_WRITE,mem)
    def code(uc,pc,size,user):
        if pc==0xa604:
            logs.append('modeled firmware logger');uc.reg_write(UC_ARM64_REG_PC,uc.reg_read(UC_ARM64_REG_LR))
    u.hook_add(UC_HOOK_CODE,code)
    return u,events,logs
def invoke(u,entry,args):
    before=[u.reg_read(r)for r in saved_regs]
    for r,x in zip(args_regs,args):u.reg_write(r,x)
    u.emu_start(entry,END,count=50000)
    assert u.reg_read(UC_ARM64_REG_PC)==END and u.reg_read(UC_ARM64_REG_SP)==STACK
    assert before==[u.reg_read(r)for r in saved_regs]
    return u.reg_read(UC_ARM64_REG_X0)&0xffffffff
results=[]
for hw,mask in [(2,0xff),(0,0xf)]:
 for word in [0,1,0xff,0x1ff,0x10000]:
  u,events,logs=setup();u.mem_write(CTX+0x10,struct.pack('<I',hw));at=MMIO+(0x20d04 if hw==2 else 0xd04);u.mem_write(at,struct.pack('<I',word));u.mem_write(ARENA,bytes([0xaa])*8)
  result=invoke(u,0x749c,[0,ARENA]);value=struct.unpack('<I',u.mem_read(ARENA,4))[0];assert result==0 and value==word&mask and events==[{'kind':'read','address':hex(at),'value':word}]
  results.append({'function':'CheckAMCFinishedIRQ','HW_DRV':hw,'input':hex(word),'output':hex(value),'status':0,'MMIO':events})
 for word in [0,1,2,3,0xffffffff]:
  u,events,logs=setup();u.mem_write(CTX+0x10,struct.pack('<I',hw));at=MMIO+(0x20d28 if hw==2 else 0xd28);u.mem_write(at,struct.pack('<I',word));u.mem_write(ARENA,bytes([0xaa])*8)
  result=invoke(u,0x6dbc,[0,0,ARENA]);value=bytes(u.mem_read(ARENA,2));assert result==0 and value==bytes([word&1,0xaa]) and events==[{'kind':'read','address':hex(at),'value':word}]
  results.append({'function':'IsTCSIdle','HW_DRV':hw,'input':hex(word),'output':value.hex(),'status':0,'MMIO':events})
 for tcs in [0,3 if hw==0 else 7]:
  u,events,logs=setup();u.mem_write(CTX+0x10,struct.pack('<I',hw));at=MMIO+(0x20d08 if hw==2 else 0xd08);result=invoke(u,0x7578,[0,tcs]);assert result==0 and events==[{'kind':'write','address':hex(at),'value':1<<tcs}]
  results.append({'function':'ClearAMCFinishedIRQ','HW_DRV':hw,'TCS':tcs,'status':0,'MMIO':events})
for name,entry,args,initialized,hw,expected in [
 ('IRQ_null',0x749c,[0,0],True,2,0xfffffffb),('IRQ_uninitialized',0x749c,[0,ARENA],False,2,0xfffffffa),('IRQ_wrong_HW',0x749c,[0,ARENA],True,1,0xfffffff8),
 ('idle_bad_TCS',0x6dbc,[0,8,ARENA],True,2,0xfffffffe),('idle_null',0x6dbc,[0,0,0],True,2,0xfffffffb),('idle_uninitialized',0x6dbc,[0,0,ARENA],False,2,0xfffffffa),
 ('clear_bad_TCS',0x7578,[0,8],True,2,0xfffffffe),('clear_uninitialized',0x7578,[0,0],False,2,0xfffffffa)]:
 u,events,logs=setup();u.mem_write(CTX,bytes([int(initialized)]));u.mem_write(CTX+0x10,struct.pack('<I',hw));result=invoke(u,entry,args);assert result==expected and not events
 results.append({'function':name,'status':hex(result),'MMIO':0})
assert len(results)==32
out={'passed':True,'cases':results,'case_count':32,'artifact_sha256':sha,'code_unmodified':True,'functions':['CheckAMCFinishedIRQ@0x749c','IsTCSIdle@0x6dbc','ClearAMCFinishedIRQ@0x7578','ContextGuard@0x6648'],'modeled_boundaries':['MMIO register contents and firmware logger@0xa604'],'facts':['HW_DRV2 IRQ reader masks8bits; HW_DRV0 masks4bits. It does not read CMD_STATUS or require its response bit16.','Idle returns bit0 of the TCS status word. IRQ clear writes the chosen TCS bit.'],'limits':['CPU execution validates compiled helper behavior; it does not newly exercise native hardware or specify SM8550 response status fields.','G73 native traces are the authority for no-response CMD_STATUS101 and exact raw/PMIC restoration.'],'native_operations':0}
a.output.write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'passed':True,'cases':32,'original_code':True,'native_operations':0}))
