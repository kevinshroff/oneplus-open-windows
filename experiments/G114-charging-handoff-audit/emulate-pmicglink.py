"""Execute original router message helpers locally; never send a real message."""
from pathlib import Path
import argparse,json,hashlib,struct
import pefile
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn.arm64_const import *
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--image',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();raw=a.image.read_bytes();assert hashlib.sha256(raw).hexdigest()=='65cd11a5e8bbf9290ba2c6767d9f0f12b160139aecae63568fabde0908c68a0b';image=pefile.PE(data=raw).get_memory_mapped_image();ARENA,END=0x30000000,0x10000000;regs=[UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3,UC_ARM64_REG_X4,UC_ARM64_REG_X5,UC_ARM64_REG_X6];rows=[]
def run(kind,value=0,transport=0,wrapper=False,length=44,capacity=10000,null=False):
 u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.mem_map(0,(len(image)+4095)&~4095);u.mem_write(0,image);u.mem_map(ARENA,0x10000);u.mem_map(END,0x1000);u.reg_write(UC_ARM64_REG_CPACR_EL1,3<<20);events=[];msg=ARENA+0x1000;out=ARENA+0x2000;bs=ARENA+0x3000
 def q(at,v):u.mem_write(at,struct.pack('<Q',v))
 def d(at,v):u.mem_write(at,struct.pack('<I',v))
 def ret(v=0):u.reg_write(UC_ARM64_REG_X0,v);u.reg_write(UC_ARM64_REG_PC,u.reg_read(UC_ARM64_REG_LR))
 def st(at):
  b=bytes(u.mem_read(at,240));return b.split(b'\0',1)[0].decode()
 q(0xe680,bs);q(bs+0x148,ARENA+0xe000);q(0xe210,0 if null else ARENA+0x5000);d(0xe1a4,capacity);d(out,0xa5a5a5a5)
 def hook(cpu,pc,size,user):
  z=[u.reg_read(r)for r in regs]
  if pc==0x2980:
   assert z[0]==1 and z[2]==24;v=list(struct.unpack('<6I',u.mem_read(z[1],24)));events.append({'modeled_router_send':v});ret(transport)
  elif pc==0x1fa0:assert z[:2]==[msg,1];events.append({'modeled_rx_done':True});ret(transport)
  elif pc==0x5564:
   e={'log':st(z[1])}
   if z[1]==0xb550:e['raw_args']=z[2:7]
   events.append(e);ret()
  elif pc==ARENA+0xe000:
   assert z[1:4]==[0xe078,0xe0c8,0];events.append({'InstallMultipleProtocolInterfaces':True,'guid_hex':bytes(u.mem_read(z[1],16)).hex(),'interface_revision':struct.unpack('<Q',u.mem_read(z[2],8))[0]});ret(transport)
 u.hook_add(UC_HOOK_CODE,hook)
 if kind=='set_uefi_load_adsp':entry=0x1da0 if wrapper else 0x36c0;args=[value]
 elif kind=='install_protocol':entry=0x16a0;args=[0x1234]
 else:
  frame=[0x800a,1,1,4,2500,5000,3700,0x55,0xaa,325,0xffffff9c]
  if kind=='short_opcode13':frame=[0x800b,1,0x13,0x12345678]
  if kind=='unknown_owner':frame[0]=0x1234
  u.mem_write(msg,struct.pack('<'+str(len(frame))+'I',*frame));entry=0x2b60;args=[msg,length,out]
 u.reg_write(UC_ARM64_REG_SP,ARENA+0xf000);u.reg_write(UC_ARM64_REG_LR,END)
 for r,v in zip(regs,args):u.reg_write(r,v)
 u.emu_start(entry,END,count=200000);assert u.reg_read(UC_ARM64_REG_PC)==END;status=u.reg_read(UC_ARM64_REG_X0);memory={hex(at):struct.unpack('<I',u.mem_read(at,4))[0]for at in [0xe22c,0xe230,0xe234,0xe238,0xe23c,0xe240,0xe244]};answer=struct.unpack('<I',u.mem_read(out,4))[0]
 if kind=='set_uefi_load_adsp':
  assert events[0]=={'modeled_router_send':[0x800a,1,0x31,0,0x23,value&0xffffffff]};assert status==(0x8000000000000007 if transport else 0)
 elif kind=='install_protocol':assert len(events)==1 and events[0]['InstallMultipleProtocolInterfaces']and status==transport
 elif null:assert status==0x8000000000000007 and not events
 elif kind=='battery_frame':
  assert status==transport
  if length==44:
   assert memory=={'0xe22c':4,'0xe230':25 if capacity else 0,'0xe234':0xffffff9c,'0xe238':3700,'0xe23c':0x55,'0xe240':0xaa,'0xe244':32}
   assert next(e['raw_args']for e in events if 'raw_args'in e)==[5000,3700,2500,325,0xffffff9c]
  else:assert all(v==0 for v in memory.values())
 elif kind=='short_opcode13':assert answer==0x12345678 and status==transport
 elif kind=='unknown_owner':assert status==transport and all(v==0 for v in memory.values())
 rows.append({'kind':kind,'value':value,'via_protocol_wrapper':wrapper,'advertised_length':length,'design_capacity_fixture':capacity,'transport_status':hex(transport),'link_null':null,'status':hex(status),'globals':memory,'out_word':hex(answer),'events':events,'native_operations':0})
for wrapper in [False,True]:
 for value in [0,1,2,0xffffffff]:run('set_uefi_load_adsp',value,wrapper=wrapper)
run('set_uefi_load_adsp',1,transport=1);run('set_uefi_load_adsp',1,transport=0x8000000000000007);run('install_protocol');run('install_protocol',transport=0x8000000000000003)
for length in [44,43,0]:run('battery_frame',length=length)
run('battery_frame',capacity=0);run('battery_frame',null=True);run('short_opcode13',length=0);run('unknown_owner')
x={'passed':True,'cases':len(rows),'image_sha256':hashlib.sha256(raw).hexdigest(),'original_installed_instructions_executed':True,'native_operations':0,'models':['router send/receive completion','UEFI protocol installation','logging'],'findings':['set_uefi_load_adsp wrapper1da0->36c0 constructs owner800a/type1/op31/power-supply0/property23/value; it is a notification through an existing router,not an ELF loader.','Module registration16a0 installs the interface; this result alone does not qualify every entry constructor or dispatch.','Valid44-byte legacy battery frame log maps raw words5rate,6voltage,4remainingcapacity,9temperature,10current; SOC uses word4*100/designcap and zero when designcap absent.','Legacy receive code can accept opcode13 with advertised length0 and acknowledge an unknown owner. A future Windows parser must add strict envelope validation; do not copy its permissive checks.'],'limits':['All frames,capacity and statuses are controlled fixtures; no real battery reading is produced.','No native GLINK send,configuration,DSP load/reset,charging change or firmware edit occurs.','Installed methods and successful local replay do not prove a usable native link or successful firmware initialization.'],'results':rows};a.output.write_text(json.dumps(x,indent=2)+'\n');print(json.dumps({k:v for k,v in x.items()if k not in ['models','findings','limits','results']}))
