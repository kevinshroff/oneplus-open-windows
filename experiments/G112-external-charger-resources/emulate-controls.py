"""Execute installed PMIC controls locally with modeled SPMI writes; never hardware."""
from pathlib import Path
import argparse,json,hashlib,struct
import pefile
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn.arm64_const import *
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--image',type=Path,required=True);p.add_argument('--native',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists()
raw=a.image.read_bytes();assert hashlib.sha256(raw).hexdigest()=='d8ac0324cdcd53a430bc617ab105a47175bbc9eb18387b9d1852c57961162a68';image=pefile.PE(data=raw).get_memory_mapped_image();packet=a.native.read_bytes();assert len(packet)==1000 and hashlib.sha256(packet).hexdigest()=='466e0e4d63b48bafdabcfe5b65f3c59f259dcb46a922e69c3bba529513cb3674';native={}
for i in range(17):
 target,off,n,flags=struct.unpack_from('<4I',packet,320+40*i);assert flags==63
 for j in range(n):native[((0x01,0x25,0x26,0x28,0x29)[target]<<8)+off+j]=packet[184+i*8+j]
ARENA,END=0x30000000,0x10000000;rows=[]
def run(entry,arg=0,missing=False,fail=False):
 u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.mem_map(0,(len(image)+4095)&~4095);u.mem_write(0,image);u.mem_map(ARENA,0x10000);u.mem_map(END,0x1000);u.reg_write(UC_ARM64_REG_CPACR_EL1,3<<20)
 comm,info,context,out=[ARENA+n for n in [0x1000,0x2000,0x3000,0x4000]];u.mem_write(comm,struct.pack('<III',7,0,0));u.mem_write(info,struct.pack('<HBBI',0x2500,2,0xa8,0));events=[]
 def ret(v=0):u.reg_write(UC_ARM64_REG_X0,v);u.reg_write(UC_ARM64_REG_PC,u.reg_read(UC_ARM64_REG_LR))
 def hook(cpu,pc,size,user):
  z=[u.reg_read(r)for r in [UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3]]
  if pc==0x1715c:assert z[:2]==[0x1d,7];ret(1)
  elif pc==0x172d0:assert z[0]==0x50;u.mem_write(z[1],struct.pack('<Q',context));ret()
  elif pc==0xdf44:
   assert z[0]==7;events.append({'modeled_masked_write':hex(z[1]),'mask':hex(z[2]),'value':hex(z[3]&255)});ret(1 if fail else 0)
  elif pc==0xdde4:
   assert z[:2]==[7,0x2640];events.append({'modeled_read':hex(z[1]),'mask':'0xff'})
   if not fail:u.mem_write(z[2],bytes([native[z[1]]]))
   ret(1 if fail else 0)
  elif pc in [0xdeb4,0xe058,0xde6c]:raise AssertionError('unexpected transport helper')
 u.hook_add(UC_HOOK_CODE,hook)
 def invoke(pc,args):
  u.reg_write(UC_ARM64_REG_SP,ARENA+0xf000);u.reg_write(UC_ARM64_REG_LR,END)
  for r,v in zip([UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3],args):u.reg_write(r,v)
  u.emu_start(pc,END,count=100000);assert u.reg_read(UC_ARM64_REG_PC)==END;return u.reg_read(UC_ARM64_REG_X0)&0xffffffff
 if not missing:invoke(0x28b90,[comm,info,7])
 status=invoke(entry,[7,out if entry==0x28618 else arg]);expected=(4 if missing else 2 if entry==0x28694 and arg>=8 else 1 if fail else 0);assert status==expected,(entry,arg,status,expected)
 if missing or(entry==0x28694 and arg>=8):assert not events
 elif entry==0x28618:
  assert len(events)==1
  if not fail:assert struct.unpack('<I',u.mem_read(out,4))[0]==3400
 else:
  want={0x28218:(0x2646,1,bool(arg)),0x28694:(0x2641,7,arg),0x28700:(0x2641,128,128 if arg else 0),0x28764:(0x2697,1,1)}[entry]
  assert len(events)==1 and events[0]=={'modeled_masked_write':hex(want[0]),'mask':hex(want[1]),'value':hex(int(want[2]))},(entry,events,want)
 rows.append({'original_entry':hex(entry),'argument':arg,'missing_context':missing,'transport_failure':fail,'status':status,'events':events,'native_operations':0})
for e in [0x28218,0x28700]:
 for arg in [0,1,255]:run(e,arg)
for arg in range(9):run(0x28694,arg)
run(0x28764);run(0x28618)
for e in [0x28218,0x28694,0x28700,0x28764,0x28618]:run(e,missing=True);run(e,fail=True)
x={'passed':True,'cases':len(rows),'original_instructions_executed':True,'PMIC_image_sha256':hashlib.sha256(raw).hexdigest(),'native_capture_sha256':hashlib.sha256(packet).hexdigest(),'native_operations':0,'models':['property lookup','allocation','SPMI masked writes and read data'],'native_control_locations':{'2646':hex(native[0x2646]),'2646_bit0_matches_boolean_setter_true':bool(native[0x2646]&1),'2641':hex(native[0x2641]),'2641_low3':native[0x2641]&7,'2641_highbit':bool(native[0x2641]&128),'2640':hex(native[0x2640]),'original_28618_native_read_result_mV':3400},'limitations':['No native control write is authorized or performed by these tests.','Existing true at the boolean command bit does not contradict the observed DISABLED state or establish its cause.','2641 low3/highbit are used in battery recovery; their full board semantics remain unresolved.','Watchdog-pet helper maps to2697,but no watchdog-expiry cause is established.','External charger population/state still requires independent evidence.'],'results':rows};a.output.write_text(json.dumps(x,indent=2)+'\n');print(json.dumps({k:v for k,v in x.items()if k not in ['results','models']}))
