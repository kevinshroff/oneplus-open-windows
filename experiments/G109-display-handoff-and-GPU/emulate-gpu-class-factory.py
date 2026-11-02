"""Exercise original GPU class factory/constructors; not a hardware-support test."""
from pathlib import Path
import argparse,hashlib,json,struct
import pefile
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn.arm64_const import *
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--image',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
a=p.parse_args();assert not a.output.exists();raw=a.image.read_bytes();identity=hashlib.sha256(raw).hexdigest()
assert identity=='cb127c49b4a61d108a1b6ae1962ef86704373e0bf81c6b5178d413fbad76f01d'
image=pefile.PE(data=raw).get_memory_mapped_image();base=0x140000000;arena=0x30000000;end=0x10000000
results=[]
for name in ['Adreno7X','Adreno6X','unknown_class','no_global','null_config','null_context_out','null_methods_out','null_flags_out']:
 u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.mem_map(base,(len(image)+4095)&~4095);u.mem_write(base,image)
 u.mem_map(arena,0x100000);u.mem_map(end,0x1000);u.reg_write(UC_ARM64_REG_SP,arena+0xf0000);u.reg_write(UC_ARM64_REG_LR,end);u.reg_write(UC_ARM64_REG_CPACR_EL1,3<<20)
 cfg,context_out,methods_out,flags_out,context=[arena+x for x in [0x1000,0x2000,0x3000,0x4000,0x5000]]
 label=name if name.startswith('Adreno') else 'Unknown' if name=='unknown_class' else 'Adreno7X'
 u.mem_write(cfg+0x280,label.encode()+b'\0');u.mem_write(0x1403164a0,struct.pack('<Q',0 if name=='no_global' else context))
 arguments=[cfg,context_out,methods_out,flags_out]
 for i,condition in enumerate(['null_config','null_context_out','null_methods_out','null_flags_out']):
  if name==condition:arguments[i]=0
 for reg,value in zip([UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3],arguments):u.reg_write(reg,value)
 ctors=[];boundaries=[]
 def ret(value=0):u.reg_write(UC_ARM64_REG_X0,value);u.reg_write(UC_ARM64_REG_PC,u.reg_read(UC_ARM64_REG_LR))
 def hook(cpu,pc,n,arg):
  if pc==0x1401be7e0:
   address,value,count=[u.reg_read(x)for x in [UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2]]
   assert address==methods_out and value==0 and count==0x148;u.mem_write(address,bytes(count));boundaries.append('memset');ret(address)
  elif pc in (0x140010a68,0x140010af8):boundaries.append('logging');ret()
  elif pc==0x14048a1a4:
   target=u.reg_read(UC_ARM64_REG_X15);assert target in (0x140495d80,0x1404a2080);boundaries.append('CFG validation');u.reg_write(UC_ARM64_REG_PC,pc+4)
  elif pc in (0x140495d80,0x1404a2080):ctors.append(hex(pc))
 u.hook_add(UC_HOOK_CODE,hook);u.emu_start(0x140489fc0,end,count=500000);assert u.reg_read(UC_ARM64_REG_PC)==end
 status=u.reg_read(UC_ARM64_REG_X0)&0xffffffff;output=struct.unpack('<Q',u.mem_read(context_out,8))[0]
 if name in ('Adreno7X','Adreno6X'):
  assert status==0 and output==context and struct.unpack('<I',u.mem_read(context+0x1d70,4))[0]==0xdeadbeef
  assert ctors==[hex(0x1404a2080 if name=='Adreno7X' else 0x140495d80)]
 elif name=='unknown_class':assert status==0xc000000e and not ctors
 elif name=='no_global':assert status==0xc0000017 and not ctors
 else:assert status==0xc000000d and not ctors
 results.append({'case':name,'status':hex(status),'constructors_executed':ctors,'modeled_boundaries':boundaries})
x={'passed':True,'cases':len(results),'driver_sha256':identity,'original_factory_and_constructors_executed':True,'native_operations':0,
   'results':results,'limits':['This proves a software class dispatch path, not Adreno740 or SM8550 compatibility.',
   'No GPU MMIO, firmware authentication, power, IOMMU, interrupt or WDDM start operation occurs.',
   'memset, logging and CFG-validation boundaries are explicitly modeled.']}
a.output.write_text(json.dumps(x,indent=2)+'\n');print(json.dumps({'passed':True,'cases':len(results),'native_operations':0}))
