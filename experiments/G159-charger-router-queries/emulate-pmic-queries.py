"""Validate original query frames and legacy receive/cache behavior offline."""
from pathlib import Path
import argparse,hashlib,json,struct
import pefile
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn.arm64_const import *

p=argparse.ArgumentParser();p.add_argument('--image',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists()
raw=a.image.read_bytes();sha=hashlib.sha256(raw).hexdigest();assert sha=='65cd11a5e8bbf9290ba2c6767d9f0f12b160139aecae63568fabde0908c68a0b'
BASE,ARENA,END=0x10000000,0x30000000,0x50000000
image=pefile.PE(data=raw).get_memory_mapped_image(ImageBase=BASE)
regs=[UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3]
rows=[]
def machine():
 u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.mem_map(BASE,(len(image)+4095)&~4095);u.mem_write(BASE,image);u.mem_map(ARENA,0x10000);u.mem_map(END,0x1000);u.reg_write(UC_ARM64_REG_CPACR_EL1,3<<20);return u
def put(u,at,v):u.mem_write(at,struct.pack('<I',v&0xffffffff))
def call(u,entry,args):
 u.reg_write(UC_ARM64_REG_SP,ARENA+0xf000);u.reg_write(UC_ARM64_REG_LR,END)
 for r,v in zip(regs,args):u.reg_write(r,v)
 u.emu_start(BASE+entry,END,count=300000);assert u.reg_read(UC_ARM64_REG_PC)==END;return u.reg_read(UC_ARM64_REG_X0)
def query(kind,status=0,index=0,null=False):
 u=machine();out=ARENA+0x1000;events=[];u.mem_write(out,b'\xa5'*32)
 for off,v in {0xe228:4,0xe230:61,0xe234:0xffffff9c,0xe238:3888,0xe244:25,0xe23c:7,0xe240:8,0xe2a0:3888}.items():put(u,BASE+off,v)
 def hook(cpu,pc,size,unused):
  if pc==BASE+0x2980:
   z=[u.reg_read(r)for r in regs];events.append({'sync_opcode_argument':z[0],'wire_bytes':z[2],'words':list(struct.unpack('<'+str(z[2]//4)+'I',u.mem_read(z[1],z[2])))})
   u.reg_write(UC_ARM64_REG_X0,status);u.reg_write(UC_ARM64_REG_PC,u.reg_read(UC_ARM64_REG_LR))
 u.hook_add(UC_HOOK_CODE,hook)
 specs={'static':(0x3310,[index],[0x800a,1,9,index],9),'state':(0x39f0,[index,0 if null else out],[0x800a,1,1,index],1),'voltage':(0x3ae0,[0 if null else out],[0x800a,1,0x30,0,6,0],0x30),'status':(0x3940,[0 if null else out],[0x800a,1,0,0],0)}
 entry,args,words,opcode=specs[kind];got=call(u,entry,args)
 if null:assert got==0x8000000000000002 and not events
 else:
  assert len(events)==1 and events[0]=={'sync_opcode_argument':opcode,'wire_bytes':len(words)*4,'words':words}
  assert got==status
  if status==0:
   expected={'state':[61,0xffffff9c,3888,25,7,8],'voltage':[3888],'status':[4]}.get(kind,[])
   if expected:assert list(struct.unpack('<'+str(len(expected))+'I',u.mem_read(out,len(expected)*4)))==expected
 rows.append({'kind':kind,'index_fixture':index,'transport_status_model':hex(status),'null_output':null,'original_result':hex(got),'events':events})
for name in ['static','state','voltage','status']:
 for st in [0,1,0x8000000000000007]:query(name,st)
for name in ['state','voltage','status']:query(name,null=True)
query('static',index=1);query('state',index=1)

def receive(opcode,length,design=20000,type_=1):
 u=machine();msg=ARENA+0x1000;out=ARENA+0x2000;events=[]
 u.mem_write(BASE+0xe210,struct.pack('<Q',ARENA+0x3000));put(u,BASE+0xe1a4,design)
 if opcode==9:words=[0x800a,type_,9,0,0,20000]+[0]*178;assert len(words)*4==736
 elif opcode==1:words=[0x800a,type_,1,4,12345,5000,3888,7,8,255,0xffffff9c]
 elif opcode==0x30:words=[0x800a,type_,0x30,6,3888000,0]
 else:words=[0x800a,type_,0,4]
 u.mem_write(msg,struct.pack('<'+str(len(words))+'I',*words))
 def hook(cpu,pc,size,unused):
  if pc==BASE+0x1fa0:
   z=[u.reg_read(r)for r in regs];assert z[:2]==[msg,1];events.append('modeled RX completion');u.reg_write(UC_ARM64_REG_X0,0);u.reg_write(UC_ARM64_REG_PC,u.reg_read(UC_ARM64_REG_LR))
  elif pc==BASE+0x5564:u.reg_write(UC_ARM64_REG_X0,0);u.reg_write(UC_ARM64_REG_PC,u.reg_read(UC_ARM64_REG_LR))
 u.hook_add(UC_HOOK_CODE,hook);got=call(u,0x2b60,[msg,length,out]);assert got==0
 cache={hex(off):struct.unpack('<I',u.mem_read(BASE+off,4))[0]for off in [0xe1a4,0xe228,0xe22c,0xe230,0xe234,0xe238,0xe244,0xe23c,0xe240,0xe2a0]}
 if opcode==9:assert cache['0xe1a4']==20000
 elif opcode==1:assert cache['0xe230']==(12345*100//design if design else 0)and cache['0xe234']==0xffffff9c and cache['0xe238']==3888 and cache['0xe244']==25
 elif opcode==0x30:assert cache['0xe2a0']==3888
 else:assert cache['0xe228']==4
 rows.append({'kind':'original-receive','opcode':opcode,'advertised_bytes':length,'type_fixture':type_,'design_capacity_fixture':design,'cache':cache,'events':events})
for opcode,length in [(9,736),(1,44),(0x30,24),(0,16)]:receive(opcode,length)
receive(1,44,design=0);receive(1,44,type_=2)
r={'passed':True,'cases':len(rows),'original_PE_sha256':sha,'native_operations':0,'native_candidate_query_order':[9,1,0x30,0],'native_candidate_index':0,'models':['Synchronous GLINK send/response completion','UEFI cached values for query wrappers','Logging'],'findings':['Query9 is16 bytes:800a/1/9/index; reply736 caches word5 as ratio denominator.','Query1 is16 bytes:800a/1/1/index; reply44 exposes raw remaining energy/rate/voltage/temperature/current.','Query30 is24 bytes:800a/1/30/0/6/0; reply24/property6 is scaled by1000 in original cache.','Query0 is16 bytes:800a/1/0/0; reply16 caches status word3.','Original receiver does not validate message type; future codec must validate exact envelope/length/opcode/property.'],'limits':['All values are controlled fixtures, not native battery readings or calibration.','No native GLINK message, battery setter, firmware or DSP operation occurs.','Source interpretations and units must remain distinct from calibrated native battery percentage/charging claims.'],'results':rows}
a.output.write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({k:v for k,v in r.items()if k not in ['models','findings','limits','results']},indent=2))
