"""Execute the original AOP status-bit5 handler with only communication mocked.

Every instruction of function e322 is original shipped Thumb code. Register
table bytes are original. Context/profile flags and bus replies are explicit
fixtures. Modeled clear writes never reach the phone.
"""
import argparse,hashlib,importlib.util,json,struct
from pathlib import Path
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_THUMB,UC_MODE_MCLASS,UC_HOOK_CODE
from unicorn.arm_const import *
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--image',type=Path,required=True);p.add_argument('--decoder',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists()
spec=importlib.util.spec_from_file_location('original_elf',a.decoder);mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod);elf=mod.Elf(a.image,mod.AOP_SHA)
ARENA,CTX,COMM,PERIPH,OUT,STACK,END=0x30000000,0x30001000,0x30002000,0x30003000,0x30004000,0x3003f000,0x10000000
profiles=[{'name':'default','flag17':0,'flag25':0,'offset':0x88,'mask':2},{'name':'flag17','flag17':1,'flag25':0,'offset':0x66,'mask':2},{'name':'flag25','flag17':0,'flag25':1,'offset':0x8b,'mask':0x10}]
def case(raw,profile,index=3,present=4,unified=1,null=False,read_failures=0,write_errors=None):
 u=Uc(UC_ARCH_ARM,UC_MODE_THUMB|UC_MODE_MCLASS);pages=set();segs=[]
 for s in elf.segments:
  va=s['va']-0xb000000 if s['va']in[0xb000000,0xb0e0000]else s['va'];segs.append((s,va));pages.update(range(va&~4095,(va+s['memsz']+4095)&~4095,4096))
 for page in sorted(pages):u.mem_map(page,4096)
 for s,va in segs:u.mem_write(va,elf.raw[s['offset']:s['offset']+s['filesz']])
 u.mem_map(ARENA,0x40000);u.mem_map(END,4096)
 def w32(at,v):u.mem_write(at,struct.pack('<I',v))
 def r32(at):return struct.unpack('<I',u.mem_read(at,4))[0]
 table=0xe138c
 assert struct.unpack('<H',u.mem_read(table+2,2))[0]==8
 assert [struct.unpack('<H',u.mem_read(table+i,2))[0]for i in [0x24,0x28,0x2a,0x30]]==[0x88,0x8b,0x66,0xd0]
 w32(CTX+4,table);w32(CTX+8,17);w32(CTX+12,PERIPH);w32(COMM,1)
 pr=PERIPH+3*28;u.mem_write(pr+12,struct.pack('<H',0xc400));u.mem_write(pr+14,bytes([present]));u.mem_write(pr+16,bytes([unified,profile['flag17']]));u.mem_write(pr+25,bytes([profile['flag25']]))
 u.mem_write(OUT,b'\xa5');u.reg_write(UC_ARM_REG_SP,STACK);u.reg_write(UC_ARM_REG_LR,END|1)
 saved_regs=[UC_ARM_REG_R4,UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_R7,UC_ARM_REG_R8,UC_ARM_REG_R9,UC_ARM_REG_R10,UC_ARM_REG_R11]
 before=[0x88000000+i*256 for i in range(8)]
 for reg,value in zip(saved_regs,before):u.reg_write(reg,value)
 for reg,value in zip([UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3],[CTX,COMM,index,0 if null else OUT]):u.reg_write(reg,value)
 calls=[];reads=0;writes=0;write_errors=write_errors or [0]*4
 def hook(uc,pc,size,unused):
  nonlocal reads,writes
  if pc not in [0xdd94,0xddf8,0xde3c]:return
  sid,at=uc.reg_read(UC_ARM_REG_R0),uc.reg_read(UC_ARM_REG_R1);assert sid==1
  if pc==0xdd94:
   reads+=1;assert at==0xc408 and uc.reg_read(UC_ARM_REG_R3)==0
   error=0x80 if reads<=read_failures else 0
   if not error:uc.mem_write(uc.reg_read(UC_ARM_REG_R2),bytes([raw]))
   calls.append({'kind':'modeled_byte_read','address':hex(at),'raw':raw,'error':error})
  else:
   value=uc.reg_read(UC_ARM_REG_R2);kind='modeled_byte_write'
   if pc==0xddf8:assert at==0xc4d0 and value==0xa5 and uc.reg_read(UC_ARM_REG_R3)==0 and writes in[0,2]
   else:
    kind='modeled_masked_write';data=uc.reg_read(UC_ARM_REG_R3)
    assert at==0xc400+profile['offset']and value==profile['mask']and data==(profile['mask']if writes==1 else 0)and writes in[1,3]
    assert r32(uc.reg_read(UC_ARM_REG_SP))==0
   error=write_errors[writes];writes+=1
   calls.append({'kind':kind,'address':hex(at),'value_or_mask':value,'data':uc.reg_read(UC_ARM_REG_R3),'error':error})
  uc.reg_write(UC_ARM_REG_R0,error);uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
 u.hook_add(UC_HOOK_CODE,hook);u.emu_start(0xe323,END,count=200000)
 assert u.reg_read(UC_ARM_REG_PC)==END and u.reg_read(UC_ARM_REG_SP)==STACK and [u.reg_read(r)for r in saved_regs]==before
 code=u.reg_read(UC_ARM_REG_R0);flag=u.mem_read(OUT,1)[0]
 valid=index<17 and present and not null and unified==1
 if not valid:
  expected=0x40 if index>=17 or not present else 2 if null else 4
  assert code==expected and reads==writes==0 and flag==0xa5
 else:
  expected_flag=0 if read_failures>=2 else (raw>>5)&1
  expected_error=0x80 if read_failures>=2 else 0
  if expected_flag:
   for error in write_errors:expected_error|=error
  assert code==expected_error and flag==expected_flag
  assert reads==min(read_failures+1,2) and writes==4*expected_flag
 return{'raw_status':raw,'profile':profile['name'],'return_code':code,'latched_flag':flag,'modeled_reads':reads,'modeled_writes':writes,'calls':calls}
total=0;critical=[]
for profile in profiles:
 for raw in range(256):
  r=case(raw,profile);total+=1
  if raw in[3,0x43,0x87,0xc7,0x20,0x60]:critical.append(r)
boundaries=[]
for kwargs in [{'index':17},{'present':0},{'unified':0},{'unified':2},{'null':True},{'read_failures':1},{'read_failures':2}]:boundaries.append(case(0x20,profiles[0],**kwargs));total+=1
for i in range(4):
 errors=[0]*4;errors[i]=1<<i;boundaries.append(case(0x20,profiles[0],write_errors=errors));total+=1
boundaries.append(case(0x20,profiles[0],write_errors=[1,2,4,8]));total+=1
priority={**profiles[2],'name':'flag25_precedes_flag17','flag17':1};boundaries.append(case(0x60,priority));total+=1
report={'passed':True,'cases':total,'all256_status_bytes_each_of_three_flag_profiles':True,'original_function':'Thumb e322..e42b','original_partition_sha256':elf.sha,'modeled_boundaries':['byte_read dd94','byte_write ddf8','masked_write de3c'],'latched_status_mask':'0x20','status43_C7_do_not_take_clear_path':True,'status03_43_same_latched_flag':True,'status87_C7_same_latched_flag':True,'current_native43_has_handler_flag0':True,'precise_status_bit6_name_established':False,'native_PMIC_clears_performed':0,'critical_cases':critical,'boundary_cases':boundaries,'limits':['Context/index3/unified and selection flags are explicit fixtures; all selection branches share bit5.','The handler role is inferred from its status-bit extraction, secure-unlock/toggle sequence and settling-error caller; original symbols are stripped.','No native AOP execution, PMIC clear operation or electrical voltage measurement.','The mask does not establish that every other status bit is harmless.']}
a.output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:report[k]for k in ['passed','cases','latched_status_mask','status43_C7_do_not_take_clear_path','precise_status_bit6_name_established']}))
