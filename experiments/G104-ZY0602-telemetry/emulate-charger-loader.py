"""Execute reference OEM charger loader ARM64 with modeled UEFI boundaries.

No firmware, DSP or native device operation occurs. This establishes the
loader's software call order only; subordinate helper effects are not proved.
"""
from pathlib import Path
import argparse,hashlib,json,struct
import pefile
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn.arm64_const import *
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--image',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists()
raw=a.image.read_bytes();sha=hashlib.sha256(raw).hexdigest();assert sha=='5722eeb57dc7d25968829f96a4e5f5b4c9664e0d458e92642e948d59591f4b6e'
pe=pefile.PE(data=raw);assert pe.FILE_HEADER.Machine==0xaa64 and pe.OPTIONAL_HEADER.ImageBase==0;image=pe.get_memory_mapped_image()
ARENA,END,LOCATE,PIL=0x30000000,0x10000000,0x10001000,0x10002000
saved=[UC_ARM64_REG_X19,UC_ARM64_REG_X20,UC_ARM64_REG_X21,UC_ARM64_REG_X22,UC_ARM64_REG_X23,UC_ARM64_REG_X24,UC_ARM64_REG_X25,UC_ARM64_REG_X26,UC_ARM64_REG_X27,UC_ARM64_REG_X28,UC_ARM64_REG_X29]
def put(u,at,fmt,*v):u.mem_write(at,struct.pack('<'+fmt,*v))
def wide(u,at):
 b=bytes(u.mem_read(at,128));n=next(i for i in range(0,len(b),2)if b[i:i+2]==b'\0\0');return b[:n].decode('utf-16le')
def run(enabled,locate=0,pre=0,mount=0,pil=0):
 u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.mem_map(0,(len(image)+4095)&~4095);u.mem_write(0,image);u.mem_map(ARENA,0x40000);u.mem_map(END,0x3000)
 put(u,0x217b0,'Q',ARENA);put(u,ARENA+0x140,'Q',LOCATE);put(u,ARENA+0x1000+8,'Q',PIL);u.mem_write(0x214e0,bytes([enabled]))
 stack=ARENA+0x3fff0;u.reg_write(UC_ARM64_REG_SP,stack);u.reg_write(UC_ARM64_REG_LR,END)
 for i,r in enumerate(saved):u.reg_write(r,0x8800000000000000+i*256)
 before=[u.reg_read(r)for r in saved];events=[]
 def ret(v):u.reg_write(UC_ARM64_REG_X0,v&0xffffffffffffffff);u.reg_write(UC_ARM64_REG_PC,u.reg_read(UC_ARM64_REG_LR))
 def code(uc,pc,size,user):
  if pc==LOCATE:
   events.append({'call':'LocateProtocol','GUID_bytes':bytes(uc.mem_read(uc.reg_read(UC_ARM64_REG_X0),16)).hex()});put(uc,uc.reg_read(UC_ARM64_REG_X2),'Q',ARENA+0x1000 if locate==0 else 0);ret(locate)
  elif pc==0xfecc:events.append({'call':'unknown_preload_helper@fecc','argument':uc.reg_read(UC_ARM64_REG_X0)});ret(pre)
  elif pc==0x8738:events.append({'call':'MountFatPartition','name':wide(uc,uc.reg_read(UC_ARM64_REG_X0))});ret(mount)
  elif pc==PIL:events.append({'call':'PIL_protocol_slot8','name':wide(uc,uc.reg_read(UC_ARM64_REG_X0))});ret(pil)
  elif pc in (0x6a34,0xdfa0,0xdfac,0xdfb4):ret(0)
 u.hook_add(UC_HOOK_CODE,code);u.emu_start(0x13094,END,count=100000);assert u.reg_read(UC_ARM64_REG_PC)==END and u.reg_read(UC_ARM64_REG_SP)==stack and before==[u.reg_read(r)for r in saved]
 result=u.reg_read(UC_ARM64_REG_X0);return {'guard_global':enabled,'locate_status':hex(locate),'pre_helper_status':hex(pre),'mount_status':hex(mount),'PIL_status':hex(pil),'result':hex(result),'events':events}
err=0x8000000000000007;rows=[]
for enabled,locate,pre,mount,pil,expected,calls in [(0,0,0,0,0,0,[]),(1,err,0,0,0,err,['LocateProtocol']),(1,0,err,0,0,err,['LocateProtocol','unknown_preload_helper@fecc']),(1,0,0,0,0,0,['LocateProtocol','unknown_preload_helper@fecc','MountFatPartition','PIL_protocol_slot8']),(1,0,0,err,0,0,['LocateProtocol','unknown_preload_helper@fecc','MountFatPartition','PIL_protocol_slot8']),(1,0,0,0,err,err,['LocateProtocol','unknown_preload_helper@fecc','MountFatPartition','PIL_protocol_slot8'])]:
 row=run(enabled,locate,pre,mount,pil);assert int(row['result'],16)==expected and [x['call']for x in row['events']]==calls
 for e in row['events']:
  if e['call']=='MountFatPartition':assert e['name']=='modem_a'
  if e['call']=='PIL_protocol_slot8':assert e['name']=='FULL_ADSP'
 rows.append(row)
out={'passed':True,'cases':len(rows),'artifact_sha256':sha,'original_ARM64_unmodified':True,'native_operations':0,'observed_function':'0x13094','modeled_boundaries':['UEFI LocateProtocol','unknown preload helper@fecc','MountFatPartition@8738','PIL protocol entry+8','logging'], 'limits':['No actual modem_a access or writes; native DSP loading is untested.','The exact meaning of the guard global and preload-helper hardware effects remain unproved.','The reference driver is absent from retained G16/G80 FFS build inventories; exact current boot_a byte identity remains a separate check.'], 'results':rows}
a.output.write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'passed':True,'cases':len(rows),'original_ARM64_unmodified':True,'native_operations':0}))
