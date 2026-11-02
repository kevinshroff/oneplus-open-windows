"""Run the reference consumer into the real installed PIL interface/parser."""
from pathlib import Path
import argparse,json,hashlib,struct,re
import pefile
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_BLOCK
from unicorn.arm64_const import *
p=argparse.ArgumentParser(description=__doc__)
for n in ['pil','consumer','config','charger-config','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();assert not a.output.exists();charger=a.charger_config.read_bytes();assert hashlib.sha256(charger).hexdigest()=='51208e088afca5e51e67a7c9575b3c4e804f34c612b4e071488e6a9609dc70de';assert re.search(rb'(?m)^EnableChargerFW\s*=\s*1\s*$',charger);raw=a.pil.read_bytes();consumer=a.consumer.read_bytes();cfg=a.config.read_bytes();sha=lambda b:hashlib.sha256(b).hexdigest();assert sha(raw)=='75dd928e1333044a9c7de275753e61b3c44ad5efb3051c62c3a12aa08f559716'and sha(consumer)=='5722eeb57dc7d25968829f96a4e5f5b4c9664e0d458e92642e948d59591f4b6e'and sha(cfg)=='13f509813bcaa5f862d0cdaa55e784c557bd0d9c9a93255185f2786a94b4c387';PIL,ARENA,END=0x50000000,0x30000000,0x10000000;pe=pefile.PE(data=raw);original_image=pe.get_memory_mapped_image();pe.relocate_image(PIL);image=pe.get_memory_mapped_image();consumer_image=pefile.PE(data=consumer).get_memory_mapped_image();regs=[UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3];rows=[]
def run(enabled=1,locate=0,pre=0,mount=0,load=0):
 u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.mem_map(0,(len(consumer_image)+4095)&~4095);u.mem_write(0,consumer_image);u.mem_map(PIL,(len(image)+4095)&~4095);u.mem_write(PIL,image);u.mem_map(ARENA,0x1000000);u.mem_map(END,0x1000);u.reg_write(UC_ARM64_REG_CPACR_EL1,3<<20);bs=ARENA+0x10000;heap=ARENA+0x40000;events=[];blocks=0;u.mem_write(ARENA+0x20000,cfg+b'\0')
 def q(at,v):u.mem_write(at,struct.pack('<Q',v))
 def ret(v=0):u.reg_write(UC_ARM64_REG_X0,v);u.reg_write(UC_ARM64_REG_PC,u.reg_read(UC_ARM64_REG_LR))
 def wide(at):
  b=bytes(u.mem_read(at,128));return b[:next((i for i in range(0,len(b),2)if b[i:i+2]==b'\0\0'),len(b))].decode('utf-16le','replace')
 q(PIL+0x1b168,bs);q(0x217b0,bs);q(bs+0x148,ARENA+0xf00000);q(bs+0x140,ARENA+0xf00004);u.mem_write(0x214e0,b'\xa5');u.mem_write(ARENA+0x8000,b'PlatformCommon\0');u.mem_write(ARENA+0x8100,b'EnableChargerFW\0');u.mem_write(ARENA+0x8200,str(enabled).encode()+b'\0')
 def hook(cpu,pc,size,user):
  nonlocal heap
  z=[u.reg_read(r)for r in regs]
  if pc==PIL+0x4cc8:ret(0)
  elif pc==PIL+0x71ec:assert wide(z[0])=='uefipil.cfg';q(z[1],ARENA+0x20000);q(z[2],len(cfg));events.append({'config_read_modeled':True});ret()
  elif pc==PIL+0x79ec:
   n=z[0];assert 0<n<=0x10000;v=heap;heap+=(n+31)&~31;assert heap<ARENA+0xc00000;ret(v)
  elif pc in [PIL+0x7b14,PIL+0x7b80,0x6a34,0xdfa0,0xdfac,0xdfb4]:ret()
  elif pc in [PIL+0x7c7c,PIL+0x4bfc,PIL+0x10d8]:raise AssertionError(('unexpected panic',hex(pc),events))
  elif pc==ARENA+0xf00000:assert z[1:4]==[PIL+0x160c8,PIL+0x16188,0];events.append({'installed_PIL_interface':True});ret()
  elif pc==ARENA+0xf00004:
   guid=bytes(u.mem_read(z[0],16));assert guid==bytes(u.mem_read(PIL+0x160c8,16));q(z[2],PIL+0x16188 if not locate else 0);events.append({'consumer_locates_actual_PIL_GUID':guid.hex()});ret(locate)
  elif pc==0xfecc:events.append({'preload_boundary_modeled':True});ret(pre)
  elif pc==0x8738:assert wide(z[0])=='modem_a';events.append({'mount_boundary_modeled':'modem_a','result':hex(mount)});ret(mount)
  elif pc==PIL+0x9bdc:assert bytes(u.mem_read(z[0],9))==b'PIL_Lock\0';q(z[1],ARENA+0x9000);events.append({'lock_create_modeled':True});ret()
  elif pc in [PIL+0x9d54,PIL+0x9d88]:assert z[0]==ARENA+0x9000;events.append({'lock_boundary':hex(pc-PIL)});ret()
  elif pc==PIL+0x1c2c:
   r=z[0];row={'actual_PIL_load_boundary_modeled':wide(r+12),'preimage':wide(r+0x174),'image_path':wide(r+0xac),'GUID_bytes':bytes(u.mem_read(r+0x9c,16)).hex(),'subsystem':struct.unpack('<I',u.mem_read(r+0xec,4))[0],'reserved_base':hex(struct.unpack('<Q',u.mem_read(r+0xf0,8))[0]),'reserved_bytes':struct.unpack('<Q',u.mem_read(r+0xf8,8))[0]};assert row['actual_PIL_load_boundary_modeled']=='full_adsp'and row['preimage'].lower()=='full_adsp_dtb'and row['image_path']==r'\image\adsp'and row['subsystem']==1 and row['reserved_base']=='0x9ea00000'and row['reserved_bytes']==0x4880000;events.append(row);ret(load)
 for off in [0x4cc8,0x71ec,0x79ec,0x7b14,0x7b80,0x7c7c,0x4bfc,0x10d8,0x9bdc,0x9d54,0x9d88,0x1c2c]:u.hook_add(UC_HOOK_CODE,hook,begin=PIL+off,end=PIL+off)
 for at in [ARENA+0xf00000,ARENA+0xf00004,0xfecc,0x8738,0x6a34,0xdfa0,0xdfac,0xdfb4]:u.hook_add(UC_HOOK_CODE,hook,begin=at,end=at)
 def unchanged_code(cpu,pc,size,user):
  nonlocal blocks
  off=pc-PIL;assert bytes(u.mem_read(pc,size))==original_image[off:off+size],hex(pc);blocks+=1
 u.hook_add(UC_HOOK_BLOCK,unchanged_code,begin=PIL,end=PIL+len(image)-1)
 def invoke(entry,args=[]):
  u.reg_write(UC_ARM64_REG_SP,ARENA+0xff0000);u.reg_write(UC_ARM64_REG_LR,END)
  for r,v in zip(regs,args):u.reg_write(r,v)
  u.emu_start(entry,END,count=5000000);assert u.reg_read(UC_ARM64_REG_PC)==END;return u.reg_read(UC_ARM64_REG_X0)
 invoke(0x4274,[ARENA+0x8000,ARENA+0x8100,ARENA+0x8200]);assert bytes(u.mem_read(0x214e0,1))==bytes([enabled]);events.append({'actual_config_callback_bound_guard_byte':enabled})
 assert invoke(PIL+0x1588)==0 and struct.unpack('<Q',u.mem_read(PIL+0x166d8,8))[0]==0 and not any('actual_PIL_load_boundary_modeled'in e for e in events)
 result=invoke(0x13094);loads=[e for e in events if 'actual_PIL_load_boundary_modeled'in e];expected=0 if not enabled else locate or pre or(0x8000000000000001 if load not in [0,9]else 0);assert result==expected and len(loads)==int(bool(enabled and not locate and not pre)),(result,expected,events)
 rows.append({'enabled':enabled,'locate_status':hex(locate),'preload_status':hex(pre),'mount_status':hex(mount),'load_boundary_status':load,'consumer_status':hex(result),'executed_original_PIL_blocks':blocks,'events':events,'native_operations':0})
err=0x8000000000000007
for values in [(0,0,0,0,0),(1,0,0,0,0),(1,err,0,0,0),(1,0,err,0,0),(1,0,0,err,0),(1,0,0,0,5),(1,0,0,0,9)]:run(*values)
x={'passed':True,'cases':len(rows),'consumer_sha256':sha(consumer),'installed_PIL_sha256':sha(raw),'installed_config_sha256':sha(cfg),'installed_charger_config_sha256':sha(charger),'actual_EnableChargerFW_callback_executed':True,'original_consumer_to_installed_PIL_parser_bridge_executed':True,'PIL_normal_PE_relocation_only':'0x50000000','executed_PIL_code_blocks_byte_identical_to_original':True,'native_operations':0,'models':['platform exclusion','config read of exact installed bytes','allocation/free/logging','UEFI install/locate','preload helper whose effects were separately audited inG106','modem_a mount','PIL lock','final actual loader boundary; no ELF/SCM work'],'limits':['Reference consumer is absent from the actual included FD; tests do not establish native execution.','Mount status is ignored by the original consumer; successful modeled selection is not real filesystem access.','No DSP load,configuration modification,firmware write or memory-ownership proof occurs.','All nativeG107 reservation/authentication and Windows handoff requirements remain unresolved.'],'results':rows};a.output.write_text(json.dumps(x,indent=2)+'\n');print(json.dumps({k:v for k,v in x.items()if k not in ['models','limits','results']}))
