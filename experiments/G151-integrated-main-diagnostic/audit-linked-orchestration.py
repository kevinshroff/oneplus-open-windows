"""Replay the compiled DTB-public/main-entry slice of the pinned G151 adapter.

Starts after independently tested source/protocol/map/hook admission and stops
before cleanup. Original PIL returns/state, protocol ownership and ZeroMem are
explicit boundaries. It does not emulate the original PIL, secure firmware or
full native boot. Every executed linked-image block is checked byte for byte.
"""
from pathlib import Path
import hashlib,json,struct
import pefile
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_BLOCK
from unicorn.arm64_const import *
w=Path(__file__).resolve().parent;p=w/'private';sha=lambda b:hashlib.sha256(b).hexdigest()
raw=(p/'BdsDxe-linked.efi').read_bytes();assert sha(raw)=='33c13aa21872dace8f5678cda89973f43c028487e0148f8bcf54e7a0796f26e5'
proof=json.loads((p/'linked-Run-REA.json').read_text());assert proof['subject']['digest']['sha256']==sha(raw)
body=proof['normalized_result']['procedure']['body'];assert body['available']and body['total_bytes']==5400 and not body['non_contiguous']
symbols=json.loads((p/'linked-symbols-all.json').read_text());assert symbols['OpenRunGuardedAdsp']=={'RVA':0x1fd70,'bytes':5400}
cfg=[(w.parent/'charging-G128/private/metadata-replay-02'/(n+'-config.bin')).read_bytes()for n in ['FULL_ADSP_DTB','FULL_ADSP']]
assert all(len(b)==568 for b in cfg)and sha(cfg[1])=='65913a28ec7082cacdaa1dca42719cdf1b748eac153d85c88cf3642961cfa992'
base,arena=0x10000000,0x90000000;entry,stop=base+0x20e24,base+0x20ed4
pe=pefile.PE(data=raw);pe.relocate_image(base);image=pe.get_memory_mapped_image()
err=lambda n:(1<<63)|n
R=lambda n:globals()['UC_ARM64_REG_X'+str(n)]
# OP_OBSERVER private source ABI; map size1656 and compiled loads agree.
fields={'active':60,'consumed':64,'busy':68,'fault':72,'count':76,'dtb_phase':80,'main_phase':84,'entered':88,'accepted':92,'complete':104}
def run(name,dtb_status=0,main_status=0,dtb=None,main=None,owner=1,owner_fault=0,missing_owner=False):
 u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.mem_map(base,(len(image)+4095)&~4095);u.mem_write(base,image);u.mem_map(arena,0x20000)
 q=lambda at,v:u.mem_write(at,struct.pack('<Q',v));dword=lambda at,v:u.mem_write(at,struct.pack('<I',v))
 getq=lambda at:struct.unpack('<Q',u.mem_read(at,8))[0];getd=lambda at:struct.unpack('<I',u.mem_read(at,4))[0]
 result=base+symbols['mResult']['RVA'];obs=base+symbols['mObserver']['RVA'];stack=arena+0x4000;first=stack+0x68;second=first+568
 pil,verify=arena+0x1000,arena+0x1010
 u.mem_write(pil,bytes.fromhex('c0035fd6'));u.mem_write(verify,bytes.fromhex('c0035fd6'))
 u.mem_write(result,bytes(9080));dword(result,9080);dword(result+4,1);u.mem_write(result+8,b'G151DSP1')
 for i in range(8):q(result+16+8*i,err(6))
 q(result+2152,err(6));dword(result+160,63);dword(result+2136,1)
 u.mem_write(obs,bytes(1656));q(obs+8,0 if missing_owner else verify);q(obs+48,0x55abc000);dword(obs+56,2)
 u.mem_write(first,cfg[0]);u.mem_write(first+0x102,b'\x01');u.mem_write(second,cfg[1]);q(stack+0x10,pil)
 for reg,value in [(22,base+0x7b000),(24,result+48),(25,result+48),(27,obs+72),(29,stack+0x600)]:u.reg_write(R(reg),value)
 u.reg_write(UC_ARM64_REG_SP,stack)
 calls=[];owners=0;clears=[];blocks=0
 def set_state(values):
  for key,value in values.items():dword(obs+fields[key],value)
 def return_to_caller(value):u.reg_write(UC_ARM64_REG_X0,value);u.reg_write(UC_ARM64_REG_PC,u.reg_read(UC_ARM64_REG_LR))
 def code(cpu,pc,size,unused):
  nonlocal owners
  if pc==pil:
   index=len(calls);assert index<2;ptr=u.reg_read(R(0));assert ptr==[first,second][index]
   actual=bytes(u.mem_read(ptr,568));expected=bytearray(cfg[index]);expected[0x102]=1
   if not index:
    assert bytes(u.mem_read(second,568))==cfg[1]and not clears and not owners
    set_state(dict(active=1,consumed=1,busy=0,fault=0,count=3,dtb_phase=3,main_phase=0,entered=1,accepted=1,complete=0))
    set_state(dtb or {})
   else:
    assert owners==1 and clears==[(second+0x174,64)]and getd(obs+104)==1
    assert getq(result+2152)==0 and getd(result+2144)==1 and getd(result+2148)==1
    expected[0x174:0x1b4]=bytes(64)
    set_state(dict(count=6,dtb_phase=3,main_phase=3,entered=3,accepted=3,fault=0))
    set_state(main or {})
   assert actual==expected;calls.append(index);return_to_caller(main_status if index else dtb_status);return
  if pc==verify:
   assert u.reg_read(R(0))==0x55abc000 and getd(obs+68)==1
   assert not clears and bytes(u.mem_read(second,568))==cfg[1]
   owners+=1;assert owners==1
   if owner_fault:dword(obs+72,owner_fault)
   return_to_caller(owner);return
  if pc==base+symbols['ZeroMem']['RVA']:
   at,n=u.reg_read(R(0)),u.reg_read(R(1));assert (at,n)==(second+0x174,64) and getd(obs+104)==1
   clears.append((at,n));u.mem_write(at,bytes(n));return_to_caller(at);return
  assert base+0x1fd70<=pc<base+0x21288,hex(pc)
 def block(cpu,pc,size,unused):
  nonlocal blocks
  if base<=pc<base+len(image):
   offset=pc-base;assert bytes(u.mem_read(pc,size))==image[offset:offset+size];blocks+=1
 u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_BLOCK,block)
 u.emu_start(entry,stop,count=4096);assert u.reg_read(UC_ARM64_REG_PC)==stop and u.reg_read(UC_ARM64_REG_SP)==stack
 dtb_state=dict(active=1,consumed=1,busy=0,fault=0,count=3,dtb_phase=3,main_phase=0,entered=1,accepted=1,complete=0);dtb_state.update(dtb or {})
 expected_gate=dtb_status==0 and all(dtb_state[k]==v for k,v in dict(active=1,consumed=1,busy=0,fault=0,count=3,dtb_phase=3,main_phase=0,entered=1,accepted=1,complete=0).items())and owner==1 and not owner_fault and not missing_owner
 assert len(calls)==(2 if expected_gate else 1)
 assert len(clears)==int(expected_gate)and getd(result+164)==len(calls)and getd(result+2140)==1
 assert getq(result+56)==dtb_status and getd(result+2160)==int(expected_gate)
 main_state=dict(dtb_phase=3,main_phase=3,entered=3,accepted=3,fault=0);main_state.update(main or {})
 expected_main=expected_gate and main_status==0 and all(main_state[k]==v for k,v in dict(dtb_phase=3,main_phase=3,accepted=3,fault=0).items())
 assert getd(result+2164)==int(expected_main)
 if expected_gate:assert getq(result+64)==main_status
 else:assert getq(result+64)==err(6)and bytes(u.mem_read(second,568))==cfg[1]
 return {'case':name,'PIL_calls_modeled':len(calls),'ownership_callbacks_modeled':owners,'main_PreImage_clear_calls_modeled':len(clears),'DTB_public_return':hex(getq(result+56)),'DTB_public_success':getd(result+2144),'DTB_marker_status':hex(getq(result+2152)),'DTB_marker_complete':getd(result+2148),'main_public_return':hex(getq(result+64)),'main_public_success':getd(result+2164),'fault':getd(obs+72),'original_blocks':blocks}
rows=[run('success'),run('DTB-public-POST-failure',dtb_status=err(7)),run('main-public-POST-failure',main_status=err(7)),run('missing-owner',missing_owner=True),run('owner-denied',owner=0),run('owner-noncanonical',owner=2),run('owner-reentrant-fault',owner_fault=2)]
for key,value in [('active',0),('consumed',0),('busy',1),('fault',8),('count',2),('count',4),('dtb_phase',2),('main_phase',1),('entered',0),('accepted',0),('complete',1)]:rows.append(run('DTB-%s-%d'%(key,value),dtb={key:value}))
for key,value in [('dtb_phase',2),('main_phase',2),('accepted',1),('fault',2048)]:rows.append(run('main-%s-%d'%(key,value),main={key:value}))
report={'passed':True,'cases':len(rows),'BDS_sha256':sha(raw),'REA_evidence_id':proof['evidence_id'],'entry_RVA':'0x20e24','stop_RVA':'0x20ed4','source_config_sha256':[sha(b)for b in cfg],'native_operations':0,'results':rows,'limits':['Actual linked AArch64 post-hook DTB public/main-entry orchestration slice; original executed blocks match pinned bytes.','Source/protocol/map/hook admission and cleanup are outside this slice and covered by the separate actual-C adapter models.','Original PIL returns/PAS state, protocol ownership and ZeroMem are modeled. Original PIL/secure firmware, actual copying/authentication and hardware ownership are not executed or qualified.','This binding does not establish native DTB/main success, DSP/GLINK or charging.']}
(p/'linked-orchestration-audit.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items()if k!='results'},indent=2))
