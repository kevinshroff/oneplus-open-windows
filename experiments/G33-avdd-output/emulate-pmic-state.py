"""Execute original PmicDxe state getters with modeled communication reads only."""
import argparse,hashlib,json,struct
from pathlib import Path
import pefile
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn.arm64_const import *
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--image',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists()
raw=a.image.read_bytes();sha=hashlib.sha256(raw).hexdigest();assert sha=='d8ac0324cdcd53a430bc617ab105a47175bbc9eb18387b9d1852c57961162a68'
pe=pefile.PE(data=raw);assert pe.OPTIONAL_HEADER.ImageBase==0 and pe.FILE_HEADER.Machine==0xaa64
image=pe.get_memory_mapped_image();ARENA,CTX,COMM,PERIPH,OUT,STACK,END=0x30000000,0x30001000,0x30002000,0x30003000,0x30004000,0x3003fff0,0x10000000
saved_regs=[UC_ARM64_REG_X19,UC_ARM64_REG_X20,UC_ARM64_REG_X21,UC_ARM64_REG_X22,UC_ARM64_REG_X23,UC_ARM64_REG_X24,UC_ARM64_REG_X25,UC_ARM64_REG_X26,UC_ARM64_REG_X27,UC_ARM64_REG_X28,UC_ARM64_REG_X29]
def case(name,entry,status=3,enable=0,unified=1,legacy=0,target=1800,active=0,index=3,present=4,null=False,status_errors=0,array_error=0):
 u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.mem_map(0,(len(image)+4095)&~4095);u.mem_write(0,image);u.mem_map(ARENA,0x40000);u.mem_map(END,4096)
 def w32(at,value):u.mem_write(at,struct.pack('<I',value))
 def w64(at,value):u.mem_write(at,struct.pack('<Q',value))
 table=0x34b20
 assert struct.unpack('<HHH',u.mem_read(table+0x10,6))==(0x40,0x41,0x42)
 assert struct.unpack('<H',u.mem_read(table+0x14,2))[0]==0x42
 w64(CTX,table);w32(CTX+0xc,17);w64(CTX+0x10,PERIPH);w32(COMM,1)
 pr=PERIPH+3*20;w32(pr,0);w32(pr+4,2000000);w32(pr+8,1000);u.mem_write(pr+12,struct.pack('<H',0xc400));u.mem_write(pr+14,bytes([present,legacy,unified]))
 u.mem_write(OUT,b'\xa5'*8);u.reg_write(UC_ARM64_REG_SP,STACK);u.reg_write(UC_ARM64_REG_LR,END);u.reg_write(UC_ARM64_REG_CPACR_EL1,3<<20)
 before=[]
 for i,r in enumerate(saved_regs):v=0x8800000000000000+i*256;before.append(v);u.reg_write(r,v)
 for r,v in zip([UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3],[CTX,COMM,index,0 if null else OUT]):u.reg_write(r,v)
 calls=[];statuscalls=0
 def hook(uc,pc,size,user):
  nonlocal statuscalls
  if pc not in [0xdde4,0xe058]:return
  sid,address=uc.reg_read(UC_ARM64_REG_W0),uc.reg_read(UC_ARM64_REG_W1);assert sid==1
  if pc==0xdde4:
   buffer=uc.reg_read(UC_ARM64_REG_X2);length=1
   assert address in [0xc408,0xc446]
   if address==0xc408:statuscalls+=1;error=0x80 if statuscalls<=status_errors else 0;value=status
   else:error=0;value=enable
   if not error:uc.mem_write(buffer,bytes([value]))
  else:
   length,buffer=uc.reg_read(UC_ARM64_REG_W2),uc.reg_read(UC_ARM64_REG_X3);assert length==2 and address in [0xc440,0xc442]
   value=target if address==0xc440 else active;error=array_error
   if not error:uc.mem_write(buffer,struct.pack('<H',value))
  calls.append({'address':hex(address),'length':length,'value':value,'modeled_error':error})
  uc.reg_write(UC_ARM64_REG_W0,error);uc.reg_write(UC_ARM64_REG_PC,uc.reg_read(UC_ARM64_REG_LR))
 u.hook_add(UC_HOOK_CODE,hook);u.emu_start(entry,END,count=200000)
 assert u.reg_read(UC_ARM64_REG_PC)==END and u.reg_read(UC_ARM64_REG_SP)==STACK and [u.reg_read(r)for r in saved_regs]==before
 ret=u.reg_read(UC_ARM64_REG_W0);value=bytes(u.mem_read(OUT,8))
 if index>=17 or not present:expected=0x20
 elif null:expected=2
 elif entry==0x152e0 and not unified:expected=4
 elif status_errors>=2 and entry in [0x150b4,0x152e0]:expected=0x80
 else:expected=array_error if entry==0x152e0 else 0
 assert ret==expected,(name,ret,expected)
 if not expected:
  mask=0x81 if not unified and legacy else 0x80;ready=int(status&mask==mask)
  if entry==0x150b4:assert value[0]==ready
  elif entry==0x15020:assert struct.unpack('<I',value[:4])[0]==enable>>7
  else:
   selected=active if ready and unified else target
   assert struct.unpack('<I',value[:4])[0]==selected*1000
   assert calls[-1]['address']==('0xc442'if ready and unified else '0xc440')
 return{'name':name,'entry':hex(entry),'status_raw':status,'unified_fixture':unified,'legacy_flag_fixture':legacy,'status_code':ret,'output_hex':value.hex(),'calls':calls}
cases=[]
for unified in [0,1]:
 for legacy in [0,1]:
  for status in [3,0x43,0x87,0xc7,0x80,0x81]:cases.append(case('ready-%d-%d-%x'%(unified,legacy,status),0x150b4,status=status,unified=unified,legacy=legacy))
for status in [3,0x43,0x87,0xc7]:
 cases.append(case('native-voltage-%x'%status,0x152e0,status=status,active=1800 if status&0x80 else 0))
 cases.append(case('discriminating-active-voltage-%x'%status,0x152e0,status=status,active=1700,target=1800))
for enable in [0,0x80]:cases.append(case('enable-%x'%enable,0x15020,enable=enable))
cases += [case('ready-retry-once',0x150b4,status=0xc7,status_errors=1),case('ready-fails-twice',0x150b4,status_errors=2),case('voltage-ready-error',0x152e0,status_errors=2),case('voltage-array-error',0x152e0,array_error=0x80),case('voltage-not-unified',0x152e0,unified=0),case('ready-null',0x150b4,null=True),case('voltage-null',0x152e0,null=True),case('invalid-index',0x150b4,index=17),case('missing',0x150b4,present=0)]
report={'image_sha256':sha,'passed':len(cases),'original_functions':['ready@0x150b4','voltage@0x152e0','enable@0x15020'],'original_ready_function_executes_inside_voltage_getter':True,'modeled_boundaries':['PMIC byte read@0xdde4','PMIC byte-array read@0xe058'],'unified_ready_mask':'0x80','ready87_equals_readyC7':True,'off03_equals_off43_for_ready_predicate':True,'voltage_uses_42_43_when_unified_and_ready_else_40_41':True,'precise_status_bit6_semantics_established':False,'cases':cases,'limits':['No native firmware getter invocation or electrical voltage measurement.','Context/peripheral min0/step1000/unified fields are explicit fixtures.','Getter behavior excludes bit6 but does not establish that bit6 is harmless.']}
a.output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:report[k]for k in ['passed','unified_ready_mask','ready87_equals_readyC7','off03_equals_off43_for_ready_predicate','voltage_uses_42_43_when_unified_and_ready_else_40_41','precise_status_bit6_semantics_established']}))
