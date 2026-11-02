"""Replay the actual compiled ReadMain/MainOwner guards, with explicit boundaries.

Protocol ownership and CopyMem are modeled. Physical target addresses remain
unmapped: a successful guard reaches a recorded copy callback, not real RAM.
Every executed original basic block is compared to the pinned linked image.
"""
from pathlib import Path
import hashlib,json,struct
import pefile
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_BLOCK
from unicorn.arm64_const import *
w=Path(__file__).resolve().parent;p=w/'private';sha=lambda b:hashlib.sha256(b).hexdigest()
raw=(p/'BdsDxe-linked.efi').read_bytes();assert sha(raw)=='33c13aa21872dace8f5678cda89973f43c028487e0148f8bcf54e7a0796f26e5'
symbols=json.loads((p/'linked-symbols-all.json').read_text())
proofs={n:json.loads((p/('linked-'+n+'-REA.json')).read_text())for n in ['ReadMain','MainOwner','plan','page-runs']}
for n,d in proofs.items():assert d['subject']['digest']['sha256']==sha(raw),n
for n in ['ReadMain','MainOwner']:
 d=proofs[n]['normalized_result'];assert int(d['procedure']['address'],16)==symbols[n]['RVA'] and d['procedure']['body']['total_bytes']==symbols[n]['bytes']
replay=(w.parent/'charging-G147/private/main-target-replay-04.json').read_bytes();assert sha(replay)=='c92416ad0eec6d8d87dd0d483238472bf5f8a53218911e590c72147e72145236'
plan=json.loads(replay)['complete_target_plan'];assert len(plan)==89
expected=b''.join(struct.pack('<IIQQ32s',1 if r['kind']=='file-copy-model'else 2,0,r['address'],r['bytes'],bytes.fromhex(r['sha256'])if r['kind']=='file-copy-model'else bytes(32))for r in plan)
for n,data in [('plan',expected),('page-runs',struct.pack('<4Q',0x9ea00000,0xa1050000,0xa109c000,0xa2837000))]:
 d=proofs[n]['normalized_result'];assert d['complete'] and bytes.fromhex(d['bytes_hex'])==data
native=pefile.PE(data=raw);assert native.get_data(symbols['mMainPlan']['RVA'],4984)==expected
base,arena,stop=0x10000000,0x90000000,0x90010000
native.relocate_image(base);image=native.get_memory_mapped_image()
saved=[globals()['UC_ARM64_REG_X'+str(i)]for i in range(19,30)]
R=lambda n:globals()['UC_ARM64_REG_X'+str(n)]
def run(name,address=0x9ea00000,n=1,**fault):
 u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.mem_map(base,(len(image)+4095)&~4095);u.mem_write(base,image);u.mem_map(arena,0x20000)
 q=lambda at,value:u.mem_write(at,struct.pack('<Q',value))
 dword=lambda at,value:u.mem_write(at,struct.pack('<I',value))
 observer=base+symbols['mObserver']['RVA'];main=base+symbols['mMain']['RVA'];scratch=base+symbols['mPayload']['RVA']+6576
 # Source ABI and REA MainOwner loads agree on these private observer fields.
 q(observer+48,0x55abc000);dword(observer+68,fault.get('busy',1));dword(observer+84,fault.get('phase',2));dword(observer+100,fault.get('copy_allowed',1));dword(observer+104,fault.get('dtb_complete',1))
 u.mem_write(base+symbols['mInitialized.514']['RVA'],bytes([fault.get('initialized',1)]))
 dword(main,368);dword(main+4,1);dword(main+16,fault.get('copy_granted',1));dword(main+20,fault.get('refreshes',1));dword(main+24,fault.get('fault',0))
 pointer=0 if fault.get('null_length')else arena+0x100;out=scratch+(8 if fault.get('wrong_buffer')else 0)
 if pointer:q(pointer,n)
 args=[observer+(8 if fault.get('wrong_context')else 0),address,pointer,out]
 for i,v in enumerate(args):u.reg_write(R(i),v)
 stack=arena+0x8000;canaries=[0x8888000000000000+256*i for i in range(len(saved))]
 for r,v in zip(saved,canaries):u.reg_write(r,v)
 u.reg_write(UC_ARM64_REG_SP,stack);u.reg_write(UC_ARM64_REG_LR,stop)
 copies=[];protocol_checks=0;blocks=0
 def ret(v):u.reg_write(UC_ARM64_REG_X0,v);u.reg_write(UC_ARM64_REG_PC,u.reg_read(UC_ARM64_REG_LR))
 def code(cpu,pc,size,unused):
  nonlocal protocol_checks
  if pc==base+symbols['VerifyOwnership']['RVA']:
   assert u.reg_read(UC_ARM64_REG_X0)==0x55abc000;protocol_checks+=1;ret(0 if fault.get('protocol_owner')==0 else 1);return
  if pc==base+symbols['CopyMem']['RVA']:
   values=tuple(u.reg_read(R(i))for i in range(3));assert values==(scratch,address,n)
   copies.append(values);u.mem_write(scratch,b'\x5a'*n);ret(scratch);return
  assert base<=pc<base+len(image),hex(pc)
 def block(cpu,pc,size,unused):
  nonlocal blocks
  if base<=pc<base+len(image):
   offset=pc-base;assert bytes(u.mem_read(pc,size))==image[offset:offset+size];blocks+=1
 u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_BLOCK,block)
 u.emu_start(base+symbols['ReadMain']['RVA'],stop,count=4096);assert u.reg_read(UC_ARM64_REG_PC)==stop
 assert u.reg_read(UC_ARM64_REG_SP)==stack and [u.reg_read(r)for r in saved]==canaries
 result=u.reg_read(UC_ARM64_REG_X0);actual=struct.unpack('<Q',u.mem_read(pointer,8))[0]if pointer else None
 allowed=not fault and any(address>=r['address']and address<r['address']+r['bytes']and n<=r['address']+r['bytes']-address for r in plan)and 0<n<=4096 and address<=(1<<64)-1-n
 assert result==(0 if allowed else 0x8000000000000002 if not pointer else 0x800000000000000f),(name,hex(result),allowed)
 assert len(copies)==int(allowed)and actual==(n if allowed else 0 if pointer else None)
 return {'case':name,'address':hex(address),'bytes':n,'status':hex(result),'copy_callbacks':len(copies),'protocol_checks_modeled':protocol_checks,'unchanged_original_blocks':blocks}
rows=[];seen=set()
for i,r in enumerate(plan):
 n=min(4096,r['bytes'])
 for label,at in [('first',r['address']),('last',r['address']+r['bytes']-n)]:
  key=(at,n)
  if key not in seen:rows.append(run('extent%d-%s'%(i,label),at,n));seen.add(key)
for name,at,n in [('c7b7000',0xc7b7000,4),('c7b7008',0xc7b7008,4),('b000000',0xb000000,4),('before-main',0x9e9fffff,1),('reservation-end',0xa3280000,1),('overflow',(1<<64)-2,4),('zero',0x9ea00000,0),('large',0x9ea00000,4097)]:rows.append(run(name,at,n))
layout=json.loads((w.parent/'charging-G147/private/main-layout-summary.json').read_text());assert layout['source_report_sha256']==sha(replay)
for i,hole in enumerate(layout['untouched_ranges']):rows.append(run('untouched%d'%i,int(hole['base'],16),1))
for name,fault in [('null-length',{'null_length':1}),('wrong-buffer',{'wrong_buffer':1}),('wrong-context',{'wrong_context':1}),('uninitialized',{'initialized':0}),('copy-not-granted',{'copy_granted':0}),('pre-refresh-missing',{'refreshes':0}),('post-refresh-already-done',{'refreshes':2}),('latched-fault',{'fault':4}),('not-busy',{'busy':0}),('no-DTB-marker',{'dtb_complete':0}),('wrong-phase-before',{'phase':1}),('wrong-phase-after',{'phase':3}),('copy-not-allowed',{'copy_allowed':0}),('protocol-owner-lost',{'protocol_owner':0})]:rows.append(run(name,**fault))
report={'passed':True,'cases':len(rows),'positive_unique_extent_ranges':len(seen),'BDS_sha256':sha(raw),'link_map_sha256':sha((p/'BdsDxe-linked.map').read_bytes()),'REA_evidence_ids':[r['evidence_id']for r in proofs.values()],'compiled_plan_bytes_match_G147':True,'compiled_main_page_runs_match':True,'native_operations':0,'results':rows,'limits':['Actual AArch64 linked ReadMain and MainOwner guard instructions; executed original basic blocks match pinned bytes.','Protocol ownership and CopyMem are explicit callbacks. Main physical addresses stay unmapped. No actual target read, UEFI lookup, AT, PAS or phone operation occurs.','Caller registers/stack and copy arguments are checked; this does not qualify full native loader orchestration, hardware ownership or DSP/GLINK/charging.']}
(p/'linked-main-read-audit.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items()if k!='results'},indent=2))
