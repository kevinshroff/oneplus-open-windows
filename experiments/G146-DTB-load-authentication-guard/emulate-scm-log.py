"""Execute the original SCM transport/error formatter with a modeled RAM sink.

Only secure-register responses, TPL, time, TZ-diag side effects and the RAM
write/read/poll callbacks are modeled. No original SCM/formatter code is patched.
"""
from pathlib import Path
import argparse,base64,hashlib,json,struct
import pefile
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_BLOCK
from unicorn.arm64_const import *
p=argparse.ArgumentParser();p.add_argument('--scm',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists()
raw=a.scm.read_bytes();digest=hashlib.sha256(raw).hexdigest();assert digest=='847b3a4cf2a8e46956a081e95d2303a65f47568094c72005db907b544f5a56ab'
SCM,ARENA,STOP=0x51000000,0x30000000,0x10000000
pe=pefile.PE(data=raw);pe.relocate_image(SCM);image=pe.get_memory_mapped_image();mask=(1<<64)-1
regs=[globals()['UC_ARM64_REG_X'+str(i)]for i in range(8)]
saved=[globals()['UC_ARM64_REG_X'+str(i)]for i in range(19,30)]
class BudgetStop(Exception):pass

def run(name,command=0x42000202,transport=(-2,),service=0,other_call=None):
 u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.mem_map(SCM,(len(image)+4095)&~4095);u.mem_write(SCM,image)
 u.mem_map(ARENA,0x100000);u.mem_map(STOP,4096);u.reg_write(UC_ARM64_REG_CPACR_EL1,3<<20)
 bs,proxy,args,result=ARENA+0x20000,ARENA+0x30000,ARENA+0x40000,ARENA+0x41000
 stack=ARENA+0xf0000;stub=ARENA+0x1000
 q=lambda at,v:u.mem_write(at,struct.pack('<Q',v&mask))
 q(SCM+0xe5a8,bs);q(bs+0x18,stub);q(bs+0x20,stub+4)
 q(SCM+0xe580,proxy);q(proxy+0x10,stub+8);q(proxy+0x28,stub+12);q(proxy+0x30,stub+16)
 values=[36,0x38000000,0]if command==0x42000201 else[36,0x9e980000,0x80000]if command==0x42000202 else[36]
 param=0x82 if command==0x42000201 else 3 if command==0x42000202 else 1
 for i in range(10):q(args+8*i,values[i]if i<len(values)else 0)
 for i in range(4):q(result+8*i,0)
 x={'case':name,'command':hex(command),'secure_entries_modeled':0,'TPL_events':[],'ticks_modeled':0,'TZ_diag_calls_modeled':0,'log_writes':[],'original_blocks':0,'other_serial_calls':[]}
 def ret(v=0):u.reg_write(UC_ARM64_REG_X0,v&mask);u.reg_write(UC_ARM64_REG_PC,u.reg_read(UC_ARM64_REG_X30))
 def code(cpu,pc,n,unused):
  z=[u.reg_read(r)for r in regs]
  if pc==stub:x['TPL_events'].append(['raise',z[0]]);assert z[0]==8;ret(4);return
  if pc==stub+4:x['TPL_events'].append(['restore',z[0]]);assert z[0]==4;ret();return
  if pc==SCM+0x6ca8:x['ticks_modeled']+=1;ret(x['ticks_modeled']);return
  if pc==SCM+0x306c:x['TZ_diag_calls_modeled']+=1;ret();return
  if pc==SCM+0x6a9c:raise AssertionError('Original serial lookup must be bypassed by the temporary RAM-sink cache')
  if pc==SCM+0x8e94:
   i=x['secure_entries_modeled'];x['secure_entries_modeled']+=1
   if i>=len(transport):raise BudgetStop('Original positive-return SMC loop exceeded the finite modeled response sequence')
   if i==0:
    expected=[command,param,*values]
    assert z[:len(expected)]==expected,(z,expected)
   for r,v in zip(regs[:7],[transport[i],service,0x2020,0x3030,0,0,0]):u.reg_write(r,v&mask)
   u.reg_write(UC_ARM64_REG_PC,pc+4);return
  if pc==stub+8:
   address,count=z[:2];assert 0<count<=512 and stack-0x4000<=address<=stack+0x100-count
   text=bytes(u.mem_read(address,count));x['log_writes'].append({'text_base64':base64.b64encode(text).decode(),'bytes':count,'within_bounded_live_stack':True,'source_stack_delta':stack-address})
   ret(count);return
  if pc in [stub+12,stub+16]:x['other_serial_calls'].append('poll'if pc==stub+12 else'read');ret();return
  assert SCM+0x1000<=pc<SCM+0xe000,('unmodeled PC',hex(pc))
 def block(cpu,pc,n,unused):
  if SCM<=pc<SCM+len(image):
   offset=pc-SCM;assert bytes(u.mem_read(pc,n))==image[offset:offset+n],('original code modified',hex(offset));x['original_blocks']+=1
 u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_BLOCK,block)
 callargs=[SCM+0xe140,command,param,args,result]
 entry=SCM+0x3f94
 if other_call=='poll':entry=SCM+0x6b9c;callargs=[]
 if other_call=='read':entry=SCM+0x6b3c;callargs=[0xc7b7000,16]
 for r,v in zip(regs,callargs+[0]*(8-len(callargs))):u.reg_write(r,v&mask)
 canaries=[0x8888000000000000+i*256 for i in range(len(saved))]
 for r,v in zip(saved,canaries):u.reg_write(r,v)
 u.reg_write(UC_ARM64_REG_SP,stack);u.reg_write(UC_ARM64_REG_X30,STOP)
 stopped=None
 try:
  u.emu_start(entry,STOP,count=2000000);assert u.reg_read(UC_ARM64_REG_PC)==STOP,'Instruction budget exhausted without a modeled stop'
  assert u.reg_read(UC_ARM64_REG_SP)==stack and[u.reg_read(r)for r in saved]==canaries
 except BudgetStop as e:stopped=str(e)
 x['model_stopped']=stopped;x['api_return']=None if stopped else hex(u.reg_read(UC_ARM64_REG_X0));x['api_results']=[hex(struct.unpack('<Q',u.mem_read(result+8*i,8))[0])for i in range(4)]
 x['transport_fixture']=[hex(v&mask)for v in transport];x['service_fixture']=hex(service&mask)
 if not other_call and not stopped:
  assert x['TPL_events']==[['raise',8],['restore',4]]and x['ticks_modeled']==2
  low=transport[-1]&0xffffffff
  expected=0 if low==0 else 0x8000000000000003 if low==0xffffffff else 0x8000000000000014 if low==0xfffffffe and service&0xffffffff==0xfffffff3 else 0x8000000000000007
  assert int(x['api_return'],16)==expected
  assert len(x['log_writes'])==int(low!=0)
  if x['log_writes']:
   b=base64.b64decode(x['log_writes'][0]['text_base64']);assert b.startswith(b'tz_armv8_smc_call failed, TzStatus = 0x')
   x['expected_printed_status32']=low;x['expected_printed_command']=command
 return x

rows=[]
for command in [0x42000201,0x42000202,0x42000205]:
 for status in [0,-1,-2,-3,-4,-5,-9,-0x80000000,0x12345678fffffffc]:rows.append(run(hex(command)+'-status-'+str(status),command=command,transport=(status,)))
rows.append(run('minus2-service-minus13',transport=(-2,),service=-13))
rows.append(run('interrupted-then-success',transport=(1,0)))
rows.append(run('nonreturning-positive-sequence',transport=(1,1,1)))
rows.append(run('serial-poll-no-data',other_call='poll'))
rows.append(run('serial-read-no-data',other_call='read'))
assert rows[-3]['model_stopped']and not rows[-3]['log_writes']
assert rows[-2]['api_return']==rows[-1]['api_return']=='0x0'and rows[-2]['other_serial_calls']==['poll']and rows[-1]['other_serial_calls']==['read']
r={'passed':True,'cases':len(rows),'SCM_sha256':digest,'original_SCM_and_formatter_instructions_unchanged':True,'native_operations':0,'results':rows,'limits':['SMC register responses, TPL, time, TZ-diag effects and serial callbacks are explicit models.','The RAM sink routes debug output; it does not forward writes or perform serial hardware lookup.','Only the original32-bit printed decision is captured; full64-bit secureX0 is not recovered.','Finite model stopping does not create a native bound on the SMC loop.']}
a.output.write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps({k:v for k,v in r.items()if k!='results'},indent=2));print(json.dumps([{'case':x['case'],'API':x['api_return'],'log_bytes':[y['bytes']for y in x['log_writes']],'text':[base64.b64decode(y['text_base64']).decode()for y in x['log_writes']]}for x in rows[:4]],indent=2))
