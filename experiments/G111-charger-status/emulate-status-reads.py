"""Run installed SCHG initializer/status/profile reads with modeled SPMI only."""
from pathlib import Path
import argparse,hashlib,json,struct
import pefile
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn.arm64_const import *
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--image',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--native',type=Path);a=p.parse_args();assert not a.output.exists()
raw=a.image.read_bytes();identity=hashlib.sha256(raw).hexdigest();assert identity=='d8ac0324cdcd53a430bc617ab105a47175bbc9eb18387b9d1852c57961162a68'
image=pefile.PE(data=raw).get_memory_mapped_image();ARENA,END=0x30000000,0x10000000
rows=[];native_values={};native_hash=None
if a.native:
 packet=a.native.read_bytes();native_hash=hashlib.sha256(packet).hexdigest();assert len(packet)==1000 and struct.unpack_from('<I',packet,124)[0]==0 and struct.unpack_from('<I',packet,148)[0]==17
 ppids=[0x701,0x725,0x726,0x728,0x729]
 for i in range(17):
  target,off,n,flags=struct.unpack_from('<4I',packet,320+40*i);assert target<5 and flags==63 and n<=8
  for j in range(n):
   address=((ppids[target]&255)<<8)+off+j;v=packet[184+8*i+j]
   assert address not in native_values or native_values[address]==v,'mixed changing native bytes need separate replay frames'
   native_values[address]=v
def run(entry,selector=0,value=0,null=False,missing=False,fail=False,native=False):
 u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.mem_map(0,(len(image)+4095)&~4095);u.mem_write(0,image);u.mem_map(ARENA,0x10000);u.mem_map(END,0x1000)
 u.reg_write(UC_ARM64_REG_CPACR_EL1,3<<20);comm,info,context,out=[ARENA+n for n in [0x1000,0x2000,0x3000,0x4000]]
 u.mem_write(comm,struct.pack('<III',7,0,0));u.mem_write(info,struct.pack('<HBBI',0x2500,2,0xa8,0));events=[]
 def ret(v=0):u.reg_write(UC_ARM64_REG_X0,v);u.reg_write(UC_ARM64_REG_PC,u.reg_read(UC_ARM64_REG_LR))
 def hook(cpu,pc,size,user):
  args=[u.reg_read(r)for r in [UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3]]
  if pc==0x1715c:assert args[:2]==[0x1d,7];ret(1)
  elif pc==0x172d0:assert args[0]==0x50;u.mem_write(args[1],struct.pack('<Q',context));ret()
  elif pc in [0xdde4,0xde6c,0xe058]:
   sid,address=args[:2];assert sid==7
   count,pointer,mask=(args[2],args[3],255)if pc==0xe058 else(1,args[2],255)if pc==0xdde4 else(1,args[3],args[2])
   events.append({'SPMI_read':hex(address),'bytes':count,'mask':hex(mask)})
   if fail:ret(1);return
   if native:data=bytes(native_values[address+i]&(mask if count==1 else 255)for i in range(count))
   elif entry==0x28278:assert address==0x2606 and count==10;data=bytes([value])*10
   else:data=bytes([value&mask])
   u.mem_write(pointer,data);ret()
  elif pc in [0xdeb4,0xdf44]:raise AssertionError('Write helper reached during READ contract')
 u.hook_add(UC_HOOK_CODE,hook)
 def invoke(start,args):
  u.reg_write(UC_ARM64_REG_SP,ARENA+0xf000);u.reg_write(UC_ARM64_REG_LR,END)
  for r,v in zip([UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3],args):u.reg_write(r,v)
  u.emu_start(start,END,count=200000);assert u.reg_read(UC_ARM64_REG_PC)==END
  return u.reg_read(UC_ARM64_REG_X0)&0xffffffff
 if not missing:invoke(0x28b90,[comm,info,7])
 args=[7,0 if null else out]
 if entry in [0x28114,0x2927c]:args=[7,selector,0 if null else out]
 status=invoke(entry,args);data=bytes(u.mem_read(out,40));expected_address={0x253f4:0x2606,0x28278:0x2606,0x2927c:0x290a,0x29308:0x290b,0x28488:0x2658,0x28114:[0x2650,0x2654,0x2660][selector]}[entry]
 if native:value=native_values[expected_address]
 if null or missing:assert status==(4 if missing else 2) and not events
 else:
  assert len(events)==(2 if entry==0x253f4 else 1) and events[0]['SPMI_read']==hex(expected_address)
  if fail:assert status==1
  else:
   assert status==0
   actual=struct.unpack_from('<I',data)[0]
   if entry==0x253f4:expected=(2 if native_values[0x2910]&1 else 3)if value&128 else 1
   elif entry==0x28278:expected=value&7
   elif entry==0x2927c:expected=value>>selector&1
   elif entry==0x29308:expected=max((i for i in range(7)if value&(1<<i)),default=7)
   elif entry==0x28488:expected=3600+(value&127)*10
   else:expected=[([100,150,200,250,300,400,500,600][value&7]),value*50,100+(value&7)*50][selector]
   if entry==0x2927c:actual=data[0]
   assert actual==expected,(entry,value,actual,expected)
 rows.append({'entry':hex(entry),'selector':selector,'input_byte':value,'null':null,'missing_context':missing,'read_failure':fail,'native_bytes_replayed':native,'status':hex(status),'read_events':events,'output_first_u32':struct.unpack_from('<I',data)[0],'output_usable':not(null or missing or fail)})
for v in range(8):run(0x28278,value=v)
run(0x28278,value=255)
for entry in [0x28278,0x2927c,0x29308,0x28114,0x28488]:
 for mode in ['null','missing','fail']:run(entry,**{mode:True})
for v in [0,1,2,4,8,16,32,64,127]:run(0x29308,value=v)
for v in [0,1]:run(0x2927c,value=v)
for selector,v in [(0,4),(1,6),(2,0)]:run(0x28114,selector,v)
for v in [0,87,127,255]:run(0x28488,value=v)
if a.native:
 for entry,selector in [(0x28278,0),(0x2927c,0),(0x29308,0),(0x28114,0),(0x28114,1),(0x28114,2),(0x28488,0),(0x253f4,0)]:run(entry,selector,native=True)
a.output.write_text(json.dumps({'passed':True,'cases':len(rows),'image_sha256':identity,'original_initializer_and_getters_executed':True,'modeled_boundaries':['property lookup','allocation','SPMI byte/array/masked reads'],'native_operations':0,'assumed_candidate_base':'0x2500','candidate_SID':7,'native_raw_sha256':native_hash,'native_family_still_unproved':not bool(a.native),'limits':['Controlled cases qualify read-address calculations and decoding; optional replay binds outputs to the saved native capture.','Failed reads can leave decoded zero outputs; outputs are unusable when status is nonzero.','No charger enable/configuration operation is qualified.'],'results':rows},indent=2)+'\n');print(json.dumps({'passed':True,'cases':len(rows),'native_operations':0}))
