"""Run the installed PIL initializer and actual INI parser with bounded models."""
from pathlib import Path
import argparse,json,hashlib,struct
import pefile
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn.arm64_const import *
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--image',type=Path,required=True);p.add_argument('--config',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();raw=a.image.read_bytes();assert hashlib.sha256(raw).hexdigest()=='75dd928e1333044a9c7de275753e61b3c44ad5efb3051c62c3a12aa08f559716';cfgraw=a.config.read_bytes();assert hashlib.sha256(cfgraw).hexdigest()=='13f509813bcaa5f862d0cdaa55e784c557bd0d9c9a93255185f2786a94b4c387';image=pefile.PE(data=raw).get_memory_mapped_image();ARENA,END=0x30000000,0x10000000;regs=[UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3,UC_ARM64_REG_X4];rows=[]
def run(auto=False,unsupported=False,read_error=False):
 u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.mem_map(0,(len(image)+4095)&~4095);u.mem_write(0,image);u.mem_map(ARENA,0x1000000);u.mem_map(END,0x1000);u.reg_write(UC_ARM64_REG_CPACR_EL1,3<<20);events=[];heap=ARENA+0x40000;bs=ARENA+0x10000;data=cfgraw.replace(b'[AUTO]\n',b'[AUTO]\nFULL_ADSP\n')if auto else cfgraw;u.mem_write(ARENA+0x20000,data+b'\0');u.mem_write(0x1b168,struct.pack('<Q',bs));u.mem_write(bs+0x148,struct.pack('<Q',ARENA+0xf00000))
 def q(at,v):u.mem_write(at,struct.pack('<Q',v))
 def d(at,v):u.mem_write(at,struct.pack('<I',v))
 def ret(v=0):u.reg_write(UC_ARM64_REG_X0,v);u.reg_write(UC_ARM64_REG_PC,u.reg_read(UC_ARM64_REG_LR))
 def ascii(at):return bytes(u.mem_read(at,256)).split(b'\0',1)[0].decode('ascii','replace')
 def wide(at):
  b=bytes(u.mem_read(at,128));return b[:next((i for i in range(0,len(b),2)if b[i:i+2]==b'\0\0'),len(b))].decode('utf-16le','replace')
 def hook(cpu,pc,size,user):
  nonlocal heap
  z=[u.reg_read(r)for r in regs]
  if pc==0x4cc8:events.append({'platform_check_modeled':True,'unsupported':unsupported});ret(int(unsupported))
  elif pc==0x71ec:
   events.append({'config_file_read_modeled':wide(z[0]),'bytes':len(data)});q(z[1],ARENA+0x20000);q(z[2],len(data));ret(0x8000000000000007 if read_error else 0)
  elif pc==0x79ec:
   n=z[0];assert 0<n<=0x10000;v=heap;heap+=(n+31)&~31;assert heap<ARENA+0xc00000;events.append({'allocation_modeled':n});ret(v)
  elif pc==0x7b14:events.append({'free_modeled':hex(z[0])});ret()
  elif pc==0x1c2c:
   name=wide(z[0]+0xc);events.append({'load_boundary_modeled':name,'record_ptr':hex(z[0])});ret()
  elif pc==0x7b80:events.append({'log':ascii(z[1])});ret()
  elif pc in [0x7c7c,0x4bfc,0x10d8]:raise AssertionError(('unexpected panic',hex(pc),events[-6:]))
  elif pc==ARENA+0xf00000:
   assert z[1:4]==[0x160c8,0x16188,0];events.append({'protocol_installed':True});ret()

 for at in [0x4cc8,0x71ec,0x79ec,0x7b14,0x1c2c,0x7b80,0x7c7c,0x4bfc,0x10d8,ARENA+0xf00000]:u.hook_add(UC_HOOK_CODE,hook,begin=at,end=at)
 u.reg_write(UC_ARM64_REG_SP,ARENA+0xff0000);u.reg_write(UC_ARM64_REG_LR,END);u.emu_start(0x1588,END,count=5000000);assert u.reg_read(UC_ARM64_REG_PC)==END;status=u.reg_read(UC_ARM64_REG_X0);count=struct.unpack('<Q',u.mem_read(0x166d8,8))[0];loads=[e for e in events if 'load_boundary_modeled'in e];installed=any('protocol_installed'in e for e in events)
 if unsupported:assert status==0x8000000000000003 and not installed and not loads
 elif read_error:assert status==0x8000000000000007 and not installed and not loads
 else:assert status==0 and installed and len(loads)==count==int(auto)
 if auto and not unsupported and not read_error:assert loads[0]['load_boundary_modeled']=='full_adsp'
 rows.append({'actual_config_with_offline_AUTO_mutation':auto,'platform_unsupported_modeled':unsupported,'file_read_error_modeled':read_error,'status':hex(status),'auto_count':count,'load_boundaries':loads,'installed':installed,'events':events,'native_operations':0})
run();run(auto=True);run(unsupported=True);run(read_error=True)
x={'passed':True,'cases':len(rows),'PILDxe_sha256':hashlib.sha256(raw).hexdigest(),'installed_config_sha256':hashlib.sha256(cfgraw).hexdigest(),'original_initializer_and_INI_parser_executed':True,'native_operations':0,'models':['platform exclusion predicate','configuration file read using the exact installed bytes or explicit local mutation','allocation/free','logging','actual loader boundary only when selected','UEFI protocol installation'],'limits':['No SCM call,physical image write,DSP start/stop,firmware or phone change occurs.','The AUTO mutation is a local test fixture,not a proposed safe firmware edit.','This qualifies startup selection if initialization is invoked; it does not prove native DXE dispatch or exclude later consumer requests.','G107 metadata,authentication/ownership and8MiB reservation conflict remain unresolved.'],'results':rows};a.output.write_text(json.dumps(x,indent=2)+'\n');print(json.dumps({k:v for k,v in x.items()if k not in ['models','limits','results']}))
