"""Execute the installed partition-child protocol publication path offline."""
from pathlib import Path
import argparse,hashlib,json,struct,uuid
import pefile
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_BLOCK
from unicorn.arm64_const import *
p=argparse.ArgumentParser(description=__doc__)
for n in ['image','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();assert not a.output.exists();raw=a.image.read_bytes();sha=lambda b:hashlib.sha256(b).hexdigest();assert sha(raw)=='a066e614fa48bb893fad774b7964c30fa8f293eafdee8e37dbdc89e1481a180b';image=pefile.PE(data=raw).get_memory_mapped_image();ARENA,END=0x30000000,0x10000000;BASIC=uuid.UUID('ebd0a0a2-b9e5-4433-87c0-68b6b72699c7').bytes_le;UNIQUE=uuid.UUID('20f0f5a3-7a66-50e4-faab-0e05dfbec961').bytes_le;GPT=BASIC+UNIQUE+struct.pack('<QQQ',0x1206,0x13e05,0)+'modem_a'.encode('utf-16le')+bytes(128-56-14);regs=[UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3,UC_ARM64_REG_X4,UC_ARM64_REG_X5,UC_ARM64_REG_X6,UC_ARM64_REG_X7];rows=[]
def run(block_ex=False,type_present=True,record_present=True,install_error=False):
 u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.mem_map(0,(len(image)+4095)&~4095);u.mem_write(0,image);u.mem_map(ARENA,0x1000000);u.mem_map(END,4096);u.reg_write(UC_ARM64_REG_CPACR_EL1,3<<20);BS=ARENA+0x10000;STUB=ARENA+0xe00000;events=[];blocks=0;heap=ARENA+0x40000;allocations=[]
 def q(at,v):u.mem_write(at,struct.pack('<Q',v))
 def d(at,v):u.mem_write(at,struct.pack('<I',v))
 def ret(v=0):u.reg_write(UC_ARM64_REG_X0,v);u.reg_write(UC_ARM64_REG_PC,u.reg_read(UC_ARM64_REG_LR))
 q(0xb2b8,BS);q(BS+0x98,STUB);q(BS+0x148,STUB+4);q(BS+0x118,STUB+8)
 parent,media,bio,bioex,path,node,info,typ,gpt=[ARENA+n for n in [0x1000,0x2000,0x3000,0x4000,0x5000,0x6000,0x7000,0x8000,0x9000]];q(parent+0x28,ARENA+0xa000);q(bio,0x10000);q(bio+8,media);u.mem_write(media,struct.pack('<I5B3xI',1,0,1,0,0,0,4096)+bytes(32));q(bioex,media);u.mem_write(path,bytes.fromhex('01041400')+bytes(16)+bytes.fromhex('7fff0400'));hd=bytes.fromhex('04012a00')+struct.pack('<IQQ',6,0x1206,0x12c00)+UNIQUE+bytes([2,2]);assert len(hd)==42;u.mem_write(node,hd);u.mem_write(info,bytes(range(144)));u.mem_write(typ,BASIC);u.mem_write(gpt,GPT);childpath=ARENA+0x50000;u.mem_write(childpath,bytes(u.mem_read(path,20))+hd+bytes.fromhex('7fff0400'));publishes=[]
 def hook(cpu,pc,size,user):
  nonlocal heap
  z=[u.reg_read(r)for r in regs]
  if pc==0x6350:
   n=z[0];assert 0x200<=n<=0x1000;v=heap;heap+=(n+31)&~31;allocations.append({'ptr':hex(v),'bytes':n});ret(v)
  elif pc==0x68e8:assert z[:2]==[path,node];events.append({'AppendDevicePathNode_modeled':True});ret(childpath)
  elif pc==0x6418:events.append({'FreePool_modeled':hex(z[0])});ret()
  elif pc==0x5598:ret()
  elif pc==0x5694:raise AssertionError('unexpected assertion')
  elif pc==STUB:
   assert z[0]==ARENA+0xb000 and bytes(u.mem_read(z[1],16))==bytes(u.mem_read(0xb0e8,16));q(z[2],0);events.append({'erase_protocol_modeled_absent':True});ret((1<<63)|3)
  elif pc==STUB+4:
   sp=u.reg_read(UC_ARM64_REG_SP);args=z+[struct.unpack('<Q',u.mem_read(sp+i*8,8))[0]for i in range(24)];pairs=[]
   for i in range(1,len(args)-1,2):
    if not args[i]:break
    pairs.append({'GUID':str(uuid.UUID(bytes_le=bytes(u.mem_read(args[i],16)))),'GUID_bytes':bytes(u.mem_read(args[i],16)).hex(),'interface':hex(args[i+1])})
   else:raise AssertionError('unterminated InstallMultipleProtocolInterfaces')
   typeguid=bytes(u.mem_read(0xb038,16));recguid=bytes(u.mem_read(0xb0d8,16));tp=next(p for p in pairs if p['GUID_bytes']==typeguid.hex());rp=next(p for p in pairs if p['GUID_bytes']==recguid.hex());tb=bytes(u.mem_read(int(tp['interface'],16),16));rb=bytes(u.mem_read(int(rp['interface'],16),128));assert tb==(BASIC if type_present else bytes(16));assert rb==(GPT if record_present else bytes(128));assert any(p['GUID_bytes']==BASIC.hex()and p['interface']=='0x0'for p in pairs)==type_present;assert recguid==bytes.fromhex('be5525fe16d78646b9d079db5921b70d');assert typeguid==bytes.fromhex('61de486861ebef4d9a8e3817cbeb8f1c');q(args[0],ARENA+0xc000);publishes.append({'pairs':pairs,'type_bytes':tb.hex(),'record_sha256':sha(rb),'record_name':rb[56:].decode('utf-16le').rstrip('\0')});events.append({'InstallMultipleProtocols_modeled_error':install_error});ret(((1<<63)|7)if install_error else 0)
  elif pc==STUB+8:events.append({'OpenParentProtocol_modeled':True});ret()
  else:raise AssertionError(hex(pc))
 for at in [0x6350,0x68e8,0x6418,0x5598,0x5694,STUB,STUB+4,STUB+8]:u.hook_add(UC_HOOK_CODE,hook,begin=at,end=at)
 def codecheck(cpu,pc,size,user):
  nonlocal blocks
  assert bytes(u.mem_read(pc,size))==image[pc:pc+size];blocks+=1
 u.hook_add(UC_HOOK_BLOCK,codecheck,begin=0x1000,end=len(image)-1)
 stack=ARENA+0xff0000;u.reg_write(UC_ARM64_REG_SP,stack);u.reg_write(UC_ARM64_REG_LR,END)
 args=[parent,ARENA+0xb000,ARENA+0xd000,ARENA+0xe000 if block_ex else 0,bio,bioex if block_ex else 0,path,node,info,0x1206,0x13e05,4096,typ if type_present else 0,gpt if record_present else 0]
 for r,v in zip(regs,args):u.reg_write(r,v)
 for i,v in enumerate(args[8:]):q(stack+i*8,v)
 u.emu_start(0x2610,END,count=500000);assert u.reg_read(UC_ARM64_REG_PC)==END;status=u.reg_read(UC_ARM64_REG_X0);assert status==(((1<<63)|7)if install_error else 0);assert len(publishes)==1;rows.append({'BlockIOEx':block_ex,'type_present':type_present,'record_present':record_present,'modeled_install_error':install_error,'status':hex(status),'original_blocks_verified':blocks,'allocations':allocations,'published':publishes[0],'events':events,'native_operations':0})
for be,tp,rp,ie in [(False,True,True,False),(True,True,True,False),(False,False,True,False),(False,True,False,False),(False,False,False,False),(False,True,True,True)]:run(be,tp,rp,ie)
x={'passed':True,'cases':len(rows),'PartitionDxe_sha256':sha(raw),'actual_partition_child_initializer_and_protocol_publication_executed':True,'models':['UEFI protocol install/open and optional erase absence','zeroed allocation/free','AppendDevicePathNode result; original record/type copies and publication remain executed'],'findings':['The installed partition driver publishes the exact custom PartitionType and PartitionRecord GUIDs consumed by PIL.','The actual publication interface points to a 128-byte GPT entry copy, with UTF16 partition name at offset0x38.','A nonzero partition type also becomes a marker protocol with NULL interface, independent of filesystem availability.'],'limits':['The input GPT entry is a local fixture using retained modem_a identity/extents, not a fresh native UEFI enumeration.','Dispatch and protocol availability in the next native boot still require preflight.','No disk IO, filesystem mount, hardware action or firmware change occurs.'],'native_operations':0,'results':rows};a.output.write_text(json.dumps(x,indent=2)+'\n');print(json.dumps({k:v for k,v in x.items()if k not in ['results','models','findings','limits']}))
