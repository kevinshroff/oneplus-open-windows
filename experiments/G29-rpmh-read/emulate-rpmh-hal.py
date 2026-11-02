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
for typ in [0,1,2]:
 for tcs,cmd in [(0,0),(2,7),(7,15)]:
    u,events,logs=setup();at=MMIO+0x20d34+tcs*672+cmd*24
    u.mem_write(at,struct.pack('<III',0xffffffff,0xffffffff,0x11223344))
    payload=struct.pack('<BBHIB3xI',cmd,4,0x804,typ,8,0x55667788);u.mem_write(ARENA,payload)
    status=invoke(u,0x7a98,[MMIO,tcs,ARENA]);assert status==0
    words=struct.unpack('<III',u.mem_read(at,12));expected=(0x10000 if typ < 2 else 0)|(0x100 if typ != 0 else 0)|8
    assert words==(expected,0x40804,0x55667788)
    assert len([e for e in events if e['kind']=='write'])==6 and len([e for e in events if e['kind']=='read'])==6
    assert {int(e['address'],16)for e in events}=={at,at+4,at+8}
    assert any(e['kind']=='read'and int(e['address'],16)==at+8 for e in events),'LDR WZR still performs DATA read'
    results.append({'case':'setup','kind':typ,'tcs':tcs,'cmd':cmd,'status':status,'words':[hex(x)for x in words],'MMIO_reads':6,'MMIO_writes':6})
for name,base,ptr,expected in [('null_base',0,ARENA,0xfffffffa),('null_command',MMIO,0,0xfffffffb)]:
    u,events,logs=setup();status=invoke(u,0x7a98,[base,0,ptr]);assert status==expected and not events;results.append({'case':name,'status':hex(status),'MMIO':0})
for name,tcs,cmd,ptr,initialized,hw,expected in [
 ('read_response',0,0,ARENA,True,2,0),('last_response',7,15,ARENA,True,2,0),
 ('bad_tcs',8,0,ARENA,True,2,0xfffffffe),('bad_cmd',0,16,ARENA,True,2,0xfffffffd),
 ('null_output',0,0,0,True,2,0xfffffffb),('uninitialized',0,0,ARENA,False,2,0xfffffffa),
 ('wrong_HW_DRV',0,0,ARENA,True,1,0xfffffff8)]:
    u,events,logs=setup();u.mem_write(CTX,bytes([int(initialized)]));u.mem_write(CTX+0x10,struct.pack('<I',hw))
    addr=MMIO+0x20d44+tcs*672+cmd*24;u.mem_write(addr,struct.pack('<I',0x1234abcd))
    status=invoke(u,0x7698,[0,tcs,cmd,ptr]);assert status==expected
    if not expected:assert struct.unpack('<I',u.mem_read(ptr,4))[0]==0x1234abcd and events==[{'kind':'read','address':hex(addr),'value':0x1234abcd}]
    else:assert not events
    results.append({'case':name,'status':hex(status),'events':events})
for name,idle,tcs,expected in [('trigger',1,0,0),('busy',0,0,0xfffffff7),('bad_trigger_tcs',1,8,0xfffffffe)]:
    u,events,logs=setup();base=MMIO+0x20d00+tcs*672
    u.mem_write(base+0x28,struct.pack('<I',idle));u.mem_write(base+0x24,struct.pack('<I',0x10000))
    status=invoke(u,0x6c2c,[0,tcs]);assert status==expected
    writes=[e for e in events if e['kind']=='write']
    if not expected:assert writes==[{'kind':'write','address':hex(base+0x24),'value':0x10000},{'kind':'write','address':hex(base+0x24),'value':0x1010000}]
    else:assert not writes
    results.append({'case':name,'status':hex(status),'events':events})
assert len(results)==21
out={'phase':'original_G17_RPMh_HAL_CPU_execution_passed','image_sha256':sha,'cases':results,'passed':len(results),
     'original_functions':['SetupDrv2Tcs@0x7a98','ReadResponseData@0x7698','TriggerTCS@0x6c2c','IsTCSIdle@0x6dbc','ContextGuard@0x6648'],
     'code_unmodified':True,'modeled_boundaries':['MMIO contents/register behavior','firmware logger@0xa604'],
     'limits':['No native TCS/RPMh request executes in these CPU tests.','Read response values are artificial; current-vote versus aggregate semantics remain unproven.','Leaf setup helper does not replace caller geometry/type validation.','Read request setup clears MSGID WRITE bit and requests response; this does not itself prove target permissions.']}
a.output.write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'passed':len(results),'original_functions':5,'native_hardware':False}))
