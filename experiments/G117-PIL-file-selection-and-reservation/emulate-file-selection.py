"""Run installed PIL config/parser, split-MDT caller, enumerator and file helpers.

Only UEFI service/protocol responses, file data, allocations, logs and time are
modeled. No native disk access, SCM, payload load or hardware action occurs.
"""
from pathlib import Path
import argparse,hashlib,json,struct,re,uuid
import pefile
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_BLOCK
from unicorn.arm64_const import *
p=argparse.ArgumentParser(description=__doc__)
for n in ['image','config','adsp','dtb','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();assert not a.output.exists();sha=lambda b:hashlib.sha256(b).hexdigest();raw=a.image.read_bytes();cfgraw=a.config.read_bytes();assert sha(raw)=='75dd928e1333044a9c7de275753e61b3c44ad5efb3051c62c3a12aa08f559716'and sha(cfgraw)=='13f509813bcaa5f862d0cdaa55e784c557bd0d9c9a93255185f2786a94b4c387';mdts={'FULL_ADSP':a.adsp.read_bytes(),'FULL_ADSP_DTB':a.dtb.read_bytes()};assert sha(mdts['FULL_ADSP'])=='353c6cbb2f0f8782d3ce91818d25e195e8402d11942b8ba18ddf70f5fae2ffb8'and sha(mdts['FULL_ADSP_DTB'])=='5476d25e617ebf2c51128fe1405d01f8731547ce14778a62893625dda7d0e0b1';image=pefile.PE(data=raw).get_memory_mapped_image();ARENA,END=0x30000000,0x10000000;EFIERR=lambda n:(1<<63)|n;BASIC=uuid.UUID('ebd0a0a2-b9e5-4433-87c0-68b6b72699c7').bytes_le;OTHER=uuid.UUID('77036cd4-03d5-42bb-8ed1-37e5a88baa34').bytes_le;regs=[UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3,UC_ARM64_REG_X4,UC_ARM64_REG_X5,UC_ARM64_REG_X6,UC_ARM64_REG_X7];rows=[]

def config(mode):
 b=cfgraw
 if mode!='installed':
  for name in ['FULL_ADSP','FULL_ADSP_DTB']:
   m=re.search(rb'(?ms)^\['+name.encode()+rb'\]\n(.*?)(?=^\[|\Z)',b);assert m;section=m[0];label=b'MoDeM_a'if mode=='label-case'else b'modem_x'if mode=='label-missing'else b'modem_a';line=b'PartiLabel = '+label+b'\n';new=re.sub(rb'(?m)^PartiGuid = .*\n',line if mode!='both-fields'else line+re.search(rb'(?m)^PartiGuid = .*\n',section)[0],section);assert new!=section;b=b[:m.start()]+new+b[m.end():]
 return b

def run(which,scenario,mode='installed',parts=None,record=True,fs=True,open_error=0,read_error=0,short=False,getinfo_error=0):
 u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.mem_map(0,(len(image)+4095)&~4095);u.mem_write(0,image);u.mem_map(ARENA,0x1000000);u.mem_map(END,4096);u.reg_write(UC_ARM64_REG_CPACR_EL1,3<<20);events=[];heap=ARENA+0x40000;blocks=0;data=config(mode);u.mem_write(ARENA+0x20000,data+b'\0');bs=ARENA+0x10000;STUB=ARENA+0xe00000;handles=[];guid=lambda at:bytes(u.mem_read(at,16));original_guid={k:guid(at)for k,at in [('block',0x16138),('devicepath',0x160f8),('type',0x16058),('record',0x16158),('sfs',0x16128),('fileinfo',0x16068)]};by_handle={};current_file=None;opened=0;closed=0;rootclosed=0
 def q(at,v):u.mem_write(at,struct.pack('<Q',v))
 def d(at,v):u.mem_write(at,struct.pack('<I',v))
 def ret(v=0):u.reg_write(UC_ARM64_REG_X0,v);u.reg_write(UC_ARM64_REG_PC,u.reg_read(UC_ARM64_REG_LR))
 def wide(at,cap=128):
  b=bytes(u.mem_read(at,cap));end=next((i for i in range(0,len(b),2)if b[i:i+2]==b'\0\0'),len(b));return b[:end].decode('utf-16le','strict')
 def putwide(at,s):u.mem_write(at,s.encode('utf-16le')+b'\0\0')
 q(0x1b168,bs)
 for off,stub in [(0x148,0),(0x138,4),(0x98,8)]:q(bs+off,STUB+stub)
 parts=parts if parts is not None else [{'name':'modem_a','type':BASIC,'fs':fs,'marker':True},{'name':'super','type':BASIC,'fs':False,'marker':True}]
 for i,part in enumerate(parts):
  h=ARENA+0x700000+i*0x2000;handles.append(h);row={**part,'i':i,'block':h+0x100,'media':h+0x180,'path':h+0x200,'type_ptr':h+0x280,'record_ptr':h+0x300,'sfs_ptr':h+0x400,'root':h+0x500,'file':h+0x600};by_handle[h]=row;q(row['block']+8,row['media']);u.mem_write(row['media'],struct.pack('<I5B3xI',1,0,1,1,0,0,4096));hd=bytearray(42);hd[:4]=bytes([4,1,42,0]);struct.pack_into('<IQQ',hd,4,i+1,0x1206,0x12c00);hd[40]=2;hd[41]=2;u.mem_write(row['path'],bytes(hd)+bytes.fromhex('7fff0400'));u.mem_write(row['type_ptr'],row['type']);u.mem_write(row['record_ptr'],row['type']+bytes(40));putwide(row['record_ptr']+0x38,row['name']);q(row['sfs_ptr']+8,STUB+12);q(row['root']+8,STUB+16);q(row['root']+16,STUB+20);q(row['file']+16,STUB+24);q(row['file']+32,STUB+28);q(row['file']+56,STUB+32);q(row['file']+64,STUB+36)
 buf=ARENA+0x680000
 for i,h in enumerate(handles):q(buf+i*8,h)
 def hook(cpu,pc,size,user):
  nonlocal heap,current_file,opened,closed,rootclosed
  z=[u.reg_read(r)for r in regs]
  if pc==0x4cc8:ret()
  elif pc==0x71ec:assert wide(z[0])=='uefipil.cfg';q(z[1],ARENA+0x20000);q(z[2],len(data));ret()
  elif pc in [0x79ec,0x795c,0xfda4]:
   n=z[0];assert 0<n<=0x10000;align=4096 if pc==0xfda4 else 32;heap=(heap+align-1)&-align;v=heap;heap+=n;assert heap<ARENA+0x600000;events.append({'modeled_allocation':hex(pc),'bytes':n});ret(v)
  elif pc in [0x7b14,0xfcd4,0x7b80]:ret()
  elif pc in [0x7c7c,0x4bfc,0x10d8]:raise AssertionError(('unexpected panic',hex(pc),events[-10:]))
  elif pc in [0x11cd4,0x11cc8,0x11ccc]:ret(1234)
  elif pc==0x4f6c:
   assert wide(z[2])=='%s.mdt';putwide(z[0],wide(z[3])+'.mdt');ret()
  elif pc==0x6bcc:
   frame=u.reg_read(UC_ARM64_REG_X29);events.append({'actual_open_wrapper_status':hex(z[0]),'actual_selected_count':struct.unpack('<I',u.mem_read(frame-0x14,4))[0]})
  elif pc==STUB:assert z[1:4]==[0x160c8,0x16188,0];events.append({'installed_PIL_protocol':True});ret()
  elif pc==STUB+4:
   assert z[0]==2 and guid(z[1])==original_guid['block'];q(z[3],len(handles));q(z[4],buf);events.append({'LocateHandleBuffer_modeled':'BlockIO','handles':[by_handle[h]['name']for h in handles]});ret()
  elif pc==STUB+8:
   assert z[0]in by_handle;row=by_handle[z[0]];g=guid(z[1]);v=0;status=0
   if g==original_guid['block']:v=row['block'];kind='BlockIO'
   elif g==original_guid['devicepath']:v=row['path'];kind='DevicePath'
   elif g==original_guid['type']:v=row['type_ptr'];kind='PartitionType'
   elif g==original_guid['record']:v=row['record_ptr']if record else 0;status=0 if record else EFIERR(3);kind='PartitionRecord'
   elif g==original_guid['sfs']:v=row['sfs_ptr']if row['fs']else 0;status=0 if row['fs']else EFIERR(3);kind='SimpleFileSystem'
   elif g==BASIC and row['type']==BASIC and row.get('marker',True):v=0;kind='type GUID marker'
   else:status=EFIERR(3);kind='absent marker'
   q(z[2],v);events.append({'HandleProtocol_modeled':kind,'partition':row['name'],'status':hex(status)});ret(status)
  elif pc==STUB+12:
   row=next(v for v in by_handle.values()if v['sfs_ptr']==z[0]);q(z[1],row['root']);events.append({'OpenVolume_modeled':row['name']});ret()
  elif pc==STUB+16:
   row=next(v for v in by_handle.values()if v['root']==z[0]);name=wide(z[2]);assert name==('\\image\\adsp.mdt'if which=='FULL_ADSP'else'\\image\\adsp_dtb.mdt')and z[3]==1 and z[4]==0;current_file=row;events.append({'OpenFile_modeled':name,'partition':row['name'],'mode':z[3]});q(z[1],row['file']if not open_error else 0)
   if not open_error:opened+=1
   ret(open_error)
  elif pc==STUB+20:rootclosed+=1;ret()
  elif pc==STUB+24:closed+=1;ret()
  elif pc==STUB+36:
   assert current_file and z[0]==current_file['file']and guid(z[1])==original_guid['fileinfo'];assert struct.unpack('<Q',u.mem_read(z[2],8))[0]>=80;q(z[3],80);q(z[3]+8,len(mdts[which]));events.append({'GetInfo_modeled_bytes':len(mdts[which]),'status':hex(getinfo_error)});ret(getinfo_error)
  elif pc==STUB+32:assert z[1]==0;events.append({'SetPosition_modeled':0});ret()
  elif pc==STUB+28:
   n=struct.unpack('<Q',u.mem_read(z[1],8))[0];assert n==len(mdts[which]);b=mdts[which][:-1]if short else mdts[which];u.mem_write(z[2],b);q(z[1],len(b));events.append({'Read_modeled_bytes':len(b),'status':hex(read_error)});ret(read_error)
  elif pc in [0x248c,0x373c,0x1c2c]:raise AssertionError('Forbidden ELF/SCM/start boundary reached')
  else:raise AssertionError(('unknown hook',hex(pc)))
 hooks=[0x4cc8,0x71ec,0x79ec,0x795c,0xfda4,0x7b14,0xfcd4,0x7b80,0x7c7c,0x4bfc,0x10d8,0x11cd4,0x11cc8,0x11ccc,0x4f6c,0x248c,0x373c,0x1c2c,0x6bcc]+list(range(STUB,STUB+40,4))
 for at in hooks:u.hook_add(UC_HOOK_CODE,hook,begin=at,end=at)
 def codecheck(cpu,pc,size,user):
  nonlocal blocks
  assert bytes(u.mem_read(pc,size))==image[pc:pc+size],hex(pc);blocks+=1
 u.hook_add(UC_HOOK_BLOCK,codecheck,begin=0x1000,end=len(image)-1)
 def invoke(entry,args=()):
  u.reg_write(UC_ARM64_REG_SP,ARENA+0xff0000);u.reg_write(UC_ARM64_REG_LR,END)
  for r,v in zip(regs,args):u.reg_write(r,v)
  u.emu_start(entry,END,count=5000000);assert u.reg_read(UC_ARM64_REG_PC)==END;return u.reg_read(UC_ARM64_REG_X0)
 assert invoke(0x1588)==0;putwide(ARENA+0x9000,which);r=invoke(0x3f58,[ARENA+0x9000]);assert r;record_guid=guid(r+0x9c);record_label=wide(r+0x4c);assert (record_guid==BASIC)==(mode in ['installed','both-fields']);assert record_label==(''if mode=='installed'else'MoDeM_a'if mode=='label-case'else'modem_x'if mode=='label-missing'else'modem_a');ctx,state=ARENA+0x8000,ARENA+0xa000;q(ctx,r);q(ctx+8,state);status=invoke(0x3144,[ctx]);outptr,n=struct.unpack('<QI',u.mem_read(state+0x30,12));read=[e for e in events if 'Read_modeled_bytes'in e];opens=[e for e in events if 'OpenFile_modeled'in e]
 expected_success=scenario in ['one-guid','label-two-guid','label-case','label-wrong-type','label-no-marker']
 assert status==(0 if expected_success else 3),(which,scenario,hex(status),events[-12:])
 if expected_success:assert outptr and bytes(u.mem_read(outptr,len(mdts[which])))==mdts[which]and len(read)==1 and len(opens)==2 and all(e['partition']=='modem_a'for e in opens)
 else:assert not outptr
 assert opened==closed,(scenario,opened,closed)
 if scenario in ['two-guid','three-guid','both-fields','label-missing','label-record-absent','label-duplicate']:assert not opens and not read
 if scenario in ['two-guid','three-guid','both-fields']:assert any(e.get('actual_open_wrapper_status')==hex(EFIERR(1))and e.get('actual_selected_count')==2 for e in events)
 rows.append({'image':which,'scenario':scenario,'config_mode':mode,'config_sha256':sha(data),'status':status,'parsed_label':record_label,'parsed_partition_GUID':str(uuid.UUID(bytes_le=record_guid)),'original_code_blocks_verified':blocks,'opened_files':opened,'closed_files':closed,'root_closes':rootclosed,'events':events,'native_operations':0})
for which in mdts:
 one=[{'name':'modem_a','type':BASIC,'fs':True,'marker':True}]
 run(which,'one-guid',parts=one);run(which,'two-guid');run(which,'three-guid',parts=one+[{'name':'super','type':BASIC,'fs':False},{'name':'another','type':BASIC,'fs':False}]);run(which,'label-two-guid',mode='label');run(which,'both-fields',mode='both-fields');run(which,'label-case',mode='label-case');run(which,'label-missing',mode='label-missing');run(which,'label-record-absent',mode='label',record=False);run(which,'label-duplicate',mode='label',parts=one+one);run(which,'label-wrong-type',mode='label',parts=[{'name':'modem_a','type':OTHER,'fs':True}]);run(which,'label-no-marker',mode='label',parts=[{'name':'modem_a','type':BASIC,'fs':True,'marker':False}]);run(which,'label-no-fs',mode='label',fs=False);run(which,'label-open-fail',mode='label',open_error=EFIERR(14));run(which,'label-read-fail',mode='label',read_error=EFIERR(7));run(which,'label-short-read',mode='label',short=True);run(which,'label-getinfo-fail',mode='label',getinfo_error=EFIERR(7))
x={'passed':True,'cases':len(rows),'PILDxe_sha256':sha(raw),'installed_config_sha256':sha(cfgraw),'original_parser_split_MDT_caller_enumerator_and_file_helpers_executed':True,'original_executed_code_blocks_unchanged':True,'models':['Platform/config file read using actual bytes or explicitly labeled local fixture','Allocation/free, formatter, log, time','UEFI handle inventory with actual Basic Data identity and named partition fixtures, protocols/device paths','SimpleFileSystem and actual saved MDT file contents','No native mounted-volume inventory is claimed'],'findings':['Generic GUID lookup counts matching BlockIO partitions before SimpleFileSystem; two matches return EFI_LOAD_ERROR before any file open.','The actual split-MDT caller ignores PartiLabel whenever PartiGuid is nonzero. Both fields together do not narrow the request.','Label-only local fixtures succeed uniquely through actual original parser/caller/enumerator/read helpers for both FULL_ADSP and FULL_ADSP_DTB.','No claim of native filesystem mount, full payload load, SCM authentication or DSP startup is made.'],'limits':['The UEFI handles and protocol availability are modeled, not a current native UEFI capture.','UEFI file-protocol responses are models; native FAT geometry remains unqualified.','File selection by label alone does not validate GPT extents or trust the contents; a controlled native preflight must bind these independently.'],'native_operations':0,'results':rows};a.output.write_text(json.dumps(x,indent=2)+'\n');print(json.dumps({k:v for k,v in x.items()if k not in ['results','models','findings','limits']}))
