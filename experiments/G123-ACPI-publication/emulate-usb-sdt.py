"""Run the original USB SDT event/notification callbacks with explicit services."""
from pathlib import Path
import argparse,hashlib,json,struct,uuid
import pefile
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn.arm64_const import UC_ARM64_REG_X0,UC_ARM64_REG_X30,UC_ARM64_REG_SP,UC_ARM64_REG_PC
ap=argparse.ArgumentParser(description=__doc__)
for n in ['binary','REA-evidence','IORT','MCFG','output']:ap.add_argument('--'+n,type=Path,required=True)
a=ap.parse_args();assert not a.output.exists();raw=a.binary.read_bytes();sha=lambda b:hashlib.sha256(b).hexdigest();assert sha(raw)=='f03c2ca932e68b1cb947b7c64c568be3b10ac0fced517153e3227a0bad48d430'
def find(x,addr,n):
 if isinstance(x,dict):
  r=x.get('normalized_result',{})
  if isinstance(r,dict)and r.get('address')==addr and r.get('returned_bytes')==n:return bytes.fromhex(r['bytes_hex'])
  for v in x.values():
   b=find(v,addr,n)
   if b is not None:return b
 elif isinstance(x,list):
  for v in x:
   b=find(v,addr,n)
   if b is not None:return b
bundle=json.loads(a.REA_evidence.read_text());pe=pefile.PE(data=raw)
for addr,n in [(0x7800,368),(0x7970,296)]:assert find(bundle,hex(addr),n)==pe.get_data(addr,n)
B=0x10000000;D=0x20000000;STACK=0x30000000;STUB=0x40000000;END=STUB+0xf00;BS=D;SDT=D+0x1000;EVENT=D+0x2000;BUF=D+0x10000;calls=[];rows=[]
u=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
for p,n in [(B,0x20000),(D,0x20000),(STACK,0x10000),(STUB,0x1000)]:u.mem_map(p,n)
pe.relocate_image(B);u.mem_write(B,pe.get_memory_mapped_image());u.mem_write(STUB,b'\xc0\x03\x5f\xd6'*1024)
def q(p):return struct.unpack('<Q',u.mem_read(p,8))[0]
def wq(p,v):u.mem_write(p,struct.pack('<Q',v))
def reg(n):return u.reg_read(UC_ARM64_REG_X0+n)
def ret(v=0):u.reg_write(UC_ARM64_REG_X0,v);u.reg_write(UC_ARM64_REG_PC,u.reg_read(UC_ARM64_REG_X30))
wq(B+0x156e8,BS);wq(BS+0x50,STUB);wq(BS+0xa8,STUB+0x10);wq(BS+0x140,STUB+0x20);wq(SDT+16,STUB+0x30)
registered_event=None;registered_table_callback=None;mode='registration';locate_fails=False

def hook(uc,pc,n,opaque):
 global registered_event,registered_table_callback
 if pc==END:uc.emu_stop();return
 if pc==STUB:
  assert reg(0)==0x200 and reg(1)==8;registered_event=reg(2);assert registered_event==B+0x7800;wq(reg(4),EVENT);calls.append('create-Event');ret();return
 if pc==STUB+0x10:
  assert bytes(uc.mem_read(reg(0),16))==uuid.UUID('eb97088e-cfdf-49c6-be4b-d906a5b20e86').bytes_le;assert reg(1)==EVENT;wq(reg(2),D+0x3000);calls.append('register-protocol-notify');ret();return
 if pc==STUB+0x20:
  assert bytes(uc.mem_read(reg(0),16))==uuid.UUID('eb97088e-cfdf-49c6-be4b-d906a5b20e86').bytes_le;calls.append('locate-SDT')
  if locate_fails:ret((1<<63)|14);return
  wq(reg(2),SDT);ret();return
 if pc==STUB+0x30:
  assert reg(0)==1;registered_table_callback=reg(1);assert registered_table_callback==B+0x78b0;calls.append('register-table-notifier');ret();return
 if pc==B+0x1d0c:calls.append('debug');ret();return
 if pc==B+0x1df4:raise AssertionError('unexpected original DEBUG assertion')
 # A direct table callback's unexpected outbound call would require its own model.
 if mode=='table' and not(B+0x78b0<=pc<B+0x7970 or pc==END):raise AssertionError(('unqualified callback path',hex(pc)))
u.hook_add(UC_HOOK_CODE,hook)
def invoke(entry,args):
 for i in range(8):u.reg_write(UC_ARM64_REG_X0+i,args[i]if i<len(args)else 0)
 u.reg_write(UC_ARM64_REG_SP,STACK+0xf000);u.reg_write(UC_ARM64_REG_X30,END);u.emu_start(entry,END+4,count=30000);assert u.reg_read(UC_ARM64_REG_PC)==END;return reg(0)
assert invoke(B+0x7970,[])==0 and registered_event and not registered_table_callback
locate_fails=True;invoke(registered_event,[EVENT,0]);assert not registered_table_callback
locate_fails=False;invoke(registered_event,[EVENT,0]);assert registered_table_callback
mode='table'
for p,want in [(a.IORT,'56a7577b86c346d5a9467ec14da1304daf0b04c48500de0782fc5479ca67f28a'),(a.MCFG,'7b69ff7edd7a23eaf943a92689f1e568ffdfeb65eb2e7b6e67b3ef3a1947ea41')]:
 b=p.read_bytes();assert sha(b)==want
 for version in [0,1,2,0x20]:
  u.mem_write(BUF,b);before=bytes(u.mem_read(BUF,len(b)));r=invoke(registered_table_callback,[BUF,version,1]);after=bytes(u.mem_read(BUF,len(b)));assert before==after
  if version==0x20:assert r==0
  rows.append({'signature':b[:4].decode(),'version':hex(version),'return':hex(r),'buffer_unchanged':True,'outbound_table_calls':0})
r=invoke(registered_table_callback,[0,0x20,1]);assert r==(1<<63)|2;rows.append({'case':'null-table','return':hex(r)})
v={'passed':True,'PE_sha256':sha(raw),'entry_bytes_match_REA':True,'event_callback_entry_observed_at_runtime':'0x7800','table_callback_entry_observed_at_runtime':'0x78b0','registration_and_protocol_delivery_calls':calls,'table_cases':rows,'models':['UEFI event creation/protocol-notify registration and explicit delivery','SDT protocol lookup/register-notify','debug-output service','captured ACPI buffers in RAM'],'scope':'This registered USB client callback leaves tested IORT/MCFG buffers unchanged, including installed version20; no complete callback roster or final Windows table is claimed.','provider_limit':'Ghidra did not recognize the event/table callback as functions. REA returned the registered code bytes; original CPU execution validates these bounded paths without decompiler claims.','native_operations':0}
a.output.write_text(json.dumps(v,indent=2)+'\n');print(json.dumps({'passed':True,'registration_delivery_exercised':True,'table_cases':len(rows),'normal_IORT_MCFG_unchanged':True,'native_operations':0}))
