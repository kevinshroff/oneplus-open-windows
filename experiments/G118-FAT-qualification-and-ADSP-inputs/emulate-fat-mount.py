"""Execute installed FAT driver start/mount using the captured BPB and FAT bytes.

UEFI services, locale selection, allocation, lock bookkeeping and failure cleanup
are explicit models. Device reads return exact captured metadata; uncaptured
bytes are refused. No native disk access, file open, write, SCM or DSP action.
"""
from pathlib import Path
import argparse,hashlib,json,struct
import pefile
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_BLOCK
from unicorn.arm64_const import *
p=argparse.ArgumentParser(description=__doc__)
for n in ['image','capture','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();assert not a.output.exists();sha=lambda b:hashlib.sha256(b).hexdigest();raw=a.image.read_bytes();assert sha(raw)=='896d1eee70e60c0eca53a2405bf8b11bf95d89108cd41aabb6ab86b631fffabd';image=pefile.PE(data=raw).get_memory_mapped_image();m=json.loads((a.capture/'capture.json').read_text());assert len(m['files'])==64 and m['FAT_metadata_unchanged']and m['GPT_copies_revalidated'];regions=[]
for row in m['metadata']:
 b=(a.capture/row['name']).read_bytes();assert len(b)==row['bytes']and sha(b)==row['sha256'];regions.append((row['offset'],b))
original=next(b for at,b in regions if at==0);assert len(original)==512 and sha(original)=='31bed7a1a7de32c927a5592552d3ef8f8ec4d7dd9b9bf7a28e8d05e4feb3c485';ARENA,END=0x30000000,0x10000000;EFIERR=lambda n:(1<<63)|n;regs=[UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3,UC_ARM64_REG_X4,UC_ARM64_REG_X5,UC_ARM64_REG_X6,UC_ARM64_REG_X7];rows=[]
def run(name,*,physical=314572800,readonly=False,mutation=None,blocksize=4096,fail_read=False):
 u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.mem_map(0,(len(image)+4095)&~4095);u.mem_write(0,image);u.mem_map(ARENA,0x2000000);u.mem_map(END,4096);u.reg_write(UC_ARM64_REG_CPACR_EL1,3<<20);events=[];allocs=[];heap=ARENA+0x100000;BS,RT,STUB=ARENA+0x10000,ARENA+0x20000,ARENA+0x1e00000;Driver,Controller,COLL,BIO,MEDIA,DISK,LANG,LIST=[ARENA+n for n in [0x1000,0x2000,0x3000,0x4000,0x5000,0x6000,0x7000,0x8000]];pub=[];writes=[];reads=[];blocks=0;boot=bytearray(original)
 if mutation:
  off,fmt,value=mutation;struct.pack_into('<'+fmt,boot,off,value)
 source=[(at,bytes(boot)if at==0 else b)for at,b in regions]
 def q(at,v):u.mem_write(at,struct.pack('<Q',v))
 def d(at,v):u.mem_write(at,struct.pack('<I',v))
 def ret(v=0):u.reg_write(UC_ARM64_REG_X0,v);u.reg_write(UC_ARM64_REG_PC,u.reg_read(UC_ARM64_REG_LR))
 def guid(at):return bytes(u.mem_read(at,16))
 q(0xf008,BS);q(0xeff8,RT);q(Driver+0x28,ARENA+0x9000);q(LIST,COLL);q(COLL+0x30,LANG);u.mem_write(LANG,b'en-US\0');q(BIO,0x10000);q(BIO+8,MEDIA);u.mem_write(MEDIA,struct.pack('<I5B3xII4xQ',1,0,1,1,int(readonly),0,blocksize,0,physical//blocksize-1));q(DISK,0x10000);q(DISK+8,STUB+24);q(DISK+16,STUB+28)
 for off,stub in [(0x138,0),(0x118,4),(0x120,8),(0x148,12),(0x170,16)]:q(BS+off,STUB+stub)
 q(RT+0x48,STUB+20)
 def hook(cpu,pc,size,user):
  nonlocal heap
  z=[u.reg_read(r)for r in regs]
  if pc in [0x3b94,0x3b88,0x3c14]:events.append({'modeled_lock_boundary':hex(pc)});ret()
  elif pc==0x174c:ret(0)
  elif pc in [0x16fc,0x164c]:raise AssertionError(('assert/log unexpectedly enabled',hex(pc),events[-8:]))
  elif pc in [0x2f4c,0x2f8c]:
   n=z[0];assert 0<n<8<<20;heap=(heap+31)&~31;v=heap;heap+=n;assert heap<ARENA+0x1800000;allocs.append({'address':hex(v),'bytes':n,'zeroed':pc==0x2f8c});ret(v)
  elif pc==0x3030:events.append({'modeled_free':hex(z[0])});ret()
  elif pc==0x18d8:assert z[0]==LANG;events.append({'modeled_language_selection':'en-US'});ret(LANG)
  elif pc==0x3d30:events.append({'modeled_failed_volume_cleanup':hex(z[0])});ret()
  elif pc==STUB:assert z[0]==2 and guid(z[1])==guid(0xee70);q(z[3],1);q(z[4],LIST);events.append({'modeled_LocateHandleBuffer':'UnicodeCollation'});ret()
  elif pc==STUB+4:
   g=guid(z[1]);h=z[0];value=0;status=0
   if h==COLL and g==guid(0xee70):value=COLL;kind='UnicodeCollation'
   elif h==Controller and g==guid(0xee20):value=BIO;kind='BlockIO'
   elif h==Controller and g==guid(0xeea0):value=DISK;kind='DiskIO'
   elif h==Controller and g==guid(0xee30):status=EFIERR(3);kind='DiskIO2 absent'
   elif h==Controller and g==guid(0xee80):status=EFIERR(3);kind='SimpleFS absent after refusal'
   else:raise AssertionError(('unexpected protocol request',hex(h),g.hex(),z))
   if z[2]:q(z[2],value)
   events.append({'modeled_OpenProtocol':kind,'status':hex(status)});ret(status)
  elif pc==STUB+8:events.append({'modeled_CloseProtocol':True});ret()
  elif pc==STUB+12:
   assert guid(z[1])==guid(0xee80);v=z[2]-24;assert struct.unpack('<Q',u.mem_read(v,8))[0]==0x76746166;total,clusters,root,fat=struct.unpack('<Q',u.mem_read(v+0x48,8))[0],struct.unpack('<Q',u.mem_read(v+0x70,8))[0],struct.unpack('<Q',u.mem_read(v+0x58,8))[0],struct.unpack('<Q',u.mem_read(v+0x50,8))[0];pub.append({'actual_volume_ptr':hex(v),'actual_volume_bytes':total,'actual_clusters':clusters,'actual_root_offset':root,'actual_fat_offset':fat,'actual_read_only':bytes(u.mem_read(v+0x44,1))[0],'actual_FAT_type':struct.unpack('<I',u.mem_read(v+0x84,4))[0],'OpenVolume_function':hex(struct.unpack('<Q',u.mem_read(z[2]+8,8))[0])});events.append({'modeled_Install_SimpleFS':True});ret()
  elif pc==STUB+16:
   assert z[0]==0x200 and z[1]==8 and z[2]==0x3c4c;q(z[5],ARENA+0xa000);events.append({'modeled_Create_pre_ExitBootServices_event':True});ret()
  elif pc==STUB+20:events.append({'modeled_PlatformLang_absent':True});ret(EFIERR(14))
  elif pc in [STUB+24,STUB+28]:
   assert z[0]==DISK and z[1]==1;off,n,dst=z[2:5]
   if pc==STUB+28:writes.append({'offset':off,'bytes':n});ret(EFIERR(8));return
   if off+n>physical or n>1<<20:events.append({'modeled_device_range_refusal':{'offset':off,'bytes':n}});ret(EFIERR(7));return
   if fail_read:events.append({'modeled_device_read_failure':True});ret(EFIERR(7));return
   for at,b in source:
    if at<=off and off+n<=at+len(b):data=b[off-at:off-at+n];break
   else:raise AssertionError(('uncaptured source bytes requested',hex(off),n))
   u.mem_write(dst,data);reads.append({'offset':off,'bytes':n,'sha256':sha(data)});ret()
  else:raise AssertionError(('unknown boundary',hex(pc)))
 ats=[0x3b94,0x3b88,0x3c14,0x174c,0x16fc,0x164c,0x2f4c,0x2f8c,0x3030,0x18d8,0x3d30]+list(range(STUB,STUB+32,4))
 for at in ats:u.hook_add(UC_HOOK_CODE,hook,begin=at,end=at)
 def codecheck(cpu,pc,size,user):
  nonlocal blocks
  assert bytes(u.mem_read(pc,size))==image[pc:pc+size],hex(pc);blocks+=1
 u.hook_add(UC_HOOK_BLOCK,codecheck,begin=0x1000,end=len(image)-1);u.reg_write(UC_ARM64_REG_SP,ARENA+0x1ff0000);u.reg_write(UC_ARM64_REG_LR,END);u.reg_write(UC_ARM64_REG_X0,Driver);u.reg_write(UC_ARM64_REG_X1,Controller);u.emu_start(0x1b08,END,count=2000000);assert u.reg_read(UC_ARM64_REG_PC)==END;status=u.reg_read(UC_ARM64_REG_X0)
 good=name in ['actual-300MiB','actual-readonly','physical-320MiB','physical-16MiB','declared-fit']
 assert (status==0)==good and len(pub)==int(good),(name,hex(status),pub,events[-8:]);assert not writes
 if good:
  assert pub[0]['actual_volume_bytes']==(314572800 if name=='declared-fit'else 335544320)and pub[0]['actual_read_only']==int(readonly)and pub[0]['OpenVolume_function']=='0x648c',(name,pub,reads)
  assert reads==[{'offset':0,'bytes':90,'sha256':sha(bytes(boot[:90]))},{'offset':4098,'bytes':2,'sha256':sha(next(b[2:4]for at,b in source if at==4096))}],(name,reads)

 rows.append({'case':name,'physical_bytes_modeled':physical,'BlockIO_blocksize':blocksize,'BlockIO_readonly':readonly,'local_BPB_mutation':mutation,'status':hex(status),'published':pub,'reads':reads,'writes':writes,'executed_original_blocks_verified':blocks,'allocations_modeled':allocs,'events':events,'native_operations':0})
run('actual-300MiB');run('actual-readonly',readonly=True);run('physical-320MiB',physical=335544320);run('physical-16MiB',physical=16<<20);run('declared-fit',mutation=(32,'I',76800));run('bad-block-size',blocksize=8192);run('bad-BPB-sector',mutation=(11,'H',4095));run('zero-total',mutation=(32,'I',0));run('bad-cluster-power',mutation=(13,'B',3));run('zero-FAT-copies',mutation=(16,'B',0));run('bad-media',mutation=(21,'B',0xf1));run('device-read-failure',fail_read=True)
x={'passed':True,'cases':len(rows),'Fat_PE_sha256':sha(raw),'captured_BPB_sha256':sha(original),'actual_driver_start_inlined_mount_and_diskIO_executed':True,'original_executed_code_blocks_unchanged':True,'native_operations':0,'findings':['With exact captured BPB/FAT bytes and modeled300MiB media, the installed driver publishes a335544320byte FAT16 volume.','The same mount succeeds with ReadOnly media and no write in the executed mount path.','A16MiB modeled device also mounts because both required reads fit: mount success alone does not validate full declared capacity.','The mount path reads90BPBbytes and2FATbytes here. No uncaptured disk bytes are synthesized.'],'models':['UEFI services/protocol interfaces and locale choice','allocation/free and lock bookkeeping','failure cleanup','pre-ExitBootServices event registration only; callback not executed','DiskIO returns exact captured metadata or explicit failure'],'limits':['This is original-code offline execution, not a native UEFI mount observation.','File opens/reads, dirty-cache behavior, ExitBootServices callback and long-term lifecycle are not qualified by these mount cases.','Physical read bounds and full64file extent validation remain required before a native request.','No filesystem repair, disk write, firmware change, authentication or DSP start occurs.'],'results':rows};a.output.write_text(json.dumps(x,indent=2)+'\n');print(json.dumps({k:v for k,v in x.items()if k not in ['findings','models','limits','results']}))
