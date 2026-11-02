"""Execute original config getter/metadata/header/allocation/free paths only.

File I/O returns the captured MDT bytes. UEFI allocation, memory attributes,
cache/NX operations and time are explicit models. No PAS request is permitted.
"""
import argparse,hashlib,json,struct
from pathlib import Path
import pefile
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_BLOCK
from unicorn.arm64_const import *

p=argparse.ArgumentParser(description=__doc__)
for n in ['image','config','adsp','dtb','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();a.output.mkdir(exist_ok=False)
sha=lambda b:hashlib.sha256(b).hexdigest()
raw=a.image.read_bytes();assert sha(raw)=='75dd928e1333044a9c7de275753e61b3c44ad5efb3051c62c3a12aa08f559716'
config=a.config.read_bytes();assert sha(config)=='7308b7ba08813cd6f693742ba1ce8a48cd5e80bcc000d045eb774837e47c0645'
mdts=[a.dtb.read_bytes(),a.adsp.read_bytes()]
assert [sha(b)for b in mdts]==['5476d25e617ebf2c51128fe1405d01f8731547ce14778a62893625dda7d0e0b1','353c6cbb2f0f8782d3ce91818d25e195e8402d11942b8ba18ddf70f5fae2ffb8']
PIL,ARENA,STOP=0x50000000,0x30000000,0x10000000
pe=pefile.PE(data=raw);original=pe.get_memory_mapped_image();pe.relocate_image(PIL);image=pe.get_memory_mapped_image()
regs=[globals()['UC_ARM64_REG_X'+str(i)]for i in range(8)]

def run(which,fault=None):
 u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.mem_map(PIL,(len(image)+4095)&~4095);u.mem_write(PIL,image);u.mem_map(ARENA,0x1000000);u.mem_map(STOP,4096)
 u.reg_write(UC_ARM64_REG_CPACR_EL1,3<<20)
 bs,ds,ctx,state,cfg=[ARENA+x for x in [0x10000,0x12000,0x1000,0x2000,0x3000]]
 q=lambda at,v:u.mem_write(at,struct.pack('<Q',v));d=lambda at,v:u.mem_write(at,struct.pack('<I',v))
 rq=lambda at:struct.unpack('<Q',u.mem_read(at,8))[0]
 rd=lambda at:struct.unpack('<I',u.mem_read(at,4))[0]
 q(PIL+0x1b168,bs);q(PIL+0x1b1d0,ds);q(bs+0x148,ARENA+0xf00000);q(bs+0x40,ARENA+0xf00004);q(bs+0x48,ARENA+0xf00008);q(bs+0x28,ARENA+0xf0000c);q(bs+0x30,ARENA+0xf00010);q(ds+0x38,ARENA+0xf00014);q(ds+0x40,ARENA+0xf00018)
 u.mem_write(ARENA+0x20000,config+b'\0')
 x={'phase':'init','heap':ARENA+0x100000,'pages':ARENA+0x400000,'pools':{},'events':[],'secure_calls':0,'blocks':0,'meta_pool_requests':0}
 name='FULL_ADSP_DTB'if which==0 else 'FULL_ADSP';filename='adsp_dtb.mdt'if which==0 else 'adsp.mdt';data=mdts[which]
 def ret(v=0):u.reg_write(UC_ARM64_REG_X0,v);u.reg_write(UC_ARM64_REG_PC,u.reg_read(UC_ARM64_REG_X30))
 def wide(at):
  b=bytes(u.mem_read(at,256));return b[:next(i for i in range(0,len(b),2)if b[i:i+2]==b'\0\0')].decode('utf-16le')
 def pool(n):
  assert 0<n<0x100000;v=x['heap'];x['heap']=(v+n+31)&~31;assert x['heap']<ARENA+0x300000;x['pools'][v]=n;return v
 def hook(cpu,pc,size,unused):
  z=[u.reg_read(r)for r in regs]
  if pc==PIL+0x248c:x['secure_calls']+=1;raise AssertionError('A PAS/SCM stage was reached')
  if pc in [PIL+0x2768,PIL+0x3478,PIL+0x373c,PIL+0x3bcc,PIL+0x49a0]:raise AssertionError(('Unexpected lifecycle stage',hex(pc)))
  if pc==PIL+0x4cc8:ret();return
  if pc==PIL+0x71ec:q(z[1],ARENA+0x20000);q(z[2],len(config));ret();return
  if pc==PIL+0x1c2c and x['phase']=='init':raise AssertionError('AUTO was not empty')
  if pc==ARENA+0xf00000:ret();return
  if pc==ARENA+0xf00004:
   assert z[0]==4
   if x['phase']=='meta':x['meta_pool_requests']+=1
   if x['phase']=='meta'and fault=='cached_alloc'and x['meta_pool_requests']==1:ret(0x8000000000000009);return
   q(z[2],pool(z[1]));ret();return
  if pc==ARENA+0xf00008:
   assert z[0]in x['pools'];del x['pools'][z[0]];ret();return
  if pc==ARENA+0xf0000c:
   assert z[0]in [0,1]and z[1]==4 and 0<z[2]<256
   v=x['pages'];x['pages']+=z[2]*4096;assert x['pages']<ARENA+0x800000;q(z[3],v);x['events'].append({'allocate_pages_model':z[2],'type':z[1]});ret();return
  if pc==ARENA+0xf00010:ret();return
  if pc==ARENA+0xf00014:
   u.mem_write(z[1],bytes(48));q(z[1],z[0]);q(z[1]+8,0x100000);q(z[1]+16,0xf);q(z[1]+24,8);ret();return
  if pc==ARENA+0xf00018:
   assert z[2]==2;x['events'].append({'memory_attribute_model':z});ret();return
  if pc in [PIL+0xf170,PIL+0x7680]:x['events'].append({'NX_or_cache_model':hex(pc-PIL),'base':hex(z[0]),'bytes':z[1]});ret();return
  if pc in [PIL+0x7b80,PIL+0x11cd4,PIL+0x62b4]:ret();return
  if pc in [PIL+0x7c7c,PIL+0x4bfc,PIL+0x10d8]:raise AssertionError(('OEM assertion',hex(pc),x['events']))
  if pc==PIL+0x4f6c:
   assert wide(z[2])=='%s.mdt';v=(wide(z[3])+'.mdt').encode('utf-16le')+b'\0\0';assert len(v)<=z[1];u.mem_write(z[0],v);ret();return
  if pc==PIL+0x6a98:
   assert wide(z[0]).rsplit('\\',1)[-1]==filename and z[1]==z[2]==0 and wide(z[3])=='adsp_ro';d(z[6],0 if fault=='size_zero'else len(data));x['events'].append({'file_size_model':filename,'label':'adsp_ro'});ret();return
  if pc==PIL+0x6cd8:
   assert wide(z[0]).rsplit('\\',1)[-1]==filename and z[1]==z[2]==0 and wide(z[3])=='adsp_ro'
   dest,cap=struct.unpack('<QQ',u.mem_read(u.reg_read(UC_ARM64_REG_SP),16));assert cap==len(data)and rq(z[6])==len(data)
   u.mem_write(dest,data);q(z[6],len(data)-1 if fault=='short_read'else len(data));x['events'].append({'read_model':filename,'bytes':len(data)});ret(0x8000000000000007 if fault=='read_error'else 0);return
  if not PIL+0x1000<=pc<PIL+0x16000:raise AssertionError(('unmodelled address',hex(pc)))
 def block(cpu,pc,size,unused):
  if PIL<=pc<PIL+len(image):assert bytes(u.mem_read(pc,size))==original[pc-PIL:pc-PIL+size];x['blocks']+=1
 u.hook_add(UC_HOOK_CODE,hook);u.hook_add(UC_HOOK_BLOCK,block)
 def call(entry,args=[]):
  for reg,v in zip(regs,list(args)+[0]*(8-len(args))):u.reg_write(reg,v)
  u.reg_write(UC_ARM64_REG_SP,ARENA+0xff0000);u.reg_write(UC_ARM64_REG_X30,STOP);u.emu_start(PIL+entry,STOP,count=3000000);assert u.reg_read(UC_ARM64_REG_PC)==STOP;return u.reg_read(UC_ARM64_REG_X0)
 assert call(0x1588)==0
 u.mem_write(ARENA+0x9000,name.encode('utf-16le')+b'\0\0');assert call(0x17e8,[ARENA+0x9000,cfg])==0
 record=bytes(u.mem_read(cfg,0x238));assert rq(cfg)==3 and rd(cfg+8)==2 and rd(cfg+0xec)==(36 if which==0 else 1)
 if not fault:(a.output/(name+'-config.bin')).write_bytes(record)
 q(ctx,cfg);q(ctx+8,state);x['phase']='meta';status=call(0x3144,[ctx]);header=None;release=None
 pointers=[rq(state+off)for off in [0x18,0x20,0x30,0x38]]
 if not fault:
  assert status==0 and all(pointers[2:]);assert bytes(u.mem_read(pointers[2],len(data)))==bytes(u.mem_read(pointers[3],len(data)))==data
  x['phase']='header';header=call(0x2200,[ctx,pointers[2]]);assert header==0
  before=rq(PIL+0x1b228);uncached=rq(state+0x38);call(0xfcd4,[uncached]);release=rq(PIL+0x1b228)-before;assert release>=len(data)
  for off in [0x18,0x20,0x30]:
   v=rq(state+off)
   if v:call(0x7b14,[v])
 else:assert status in [3,8] and not any(pointers)
 assert not x['secure_calls']
 return {'image':name,'fault':fault,'PIL_metadata_status':status,'CPU_header_status':header,'MDT_bytes':len(data),'MDT_sha256':sha(data),'config_sha256':sha(record),'uncached_reuse_bytes_after_release':release,'remaining_pools_model':len(x['pools']),'events':x['events'],'original_blocks':x['blocks'],'PAS_calls':0}

rows=[]
for i in [0,1]:
 for f in [None,'size_zero','cached_alloc','short_read','read_error']:
  rows.append(run(i,f));print(json.dumps({'completed_image':i,'fault':f}),flush=True)
r={'passed':True,'cases':len(rows),'PIL_sha256':sha(raw),'config_sha256':sha(config),'results':rows,'native_phone_operations':0,'scope':'Original config getter, metadata/header helpers and uncached allocation/reuse/free code execute. Files/UEFI allocation/cache/NX/GCD attributes/time are modeled. No public load, shutdown or PAS stage is called. No native memory ownership or authentication claim.'}
(a.output/'tests.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({'passed':True,'cases':len(rows),'PAS_calls':0}))
