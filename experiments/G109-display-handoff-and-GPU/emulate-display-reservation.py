"""Execute installed display UI reservation code; no native access or firmware init."""
from pathlib import Path
import argparse,hashlib,json
import pefile
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn.arm64_const import *
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--image',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
a=p.parse_args();assert not a.output.exists()
raw=a.image.read_bytes();identity=hashlib.sha256(raw).hexdigest()
assert identity=='b5c9a18cf255615568abfbbd78a631d36810d0dbd12fb0c8b8ed7dc0c46962a2'
image=pefile.PE(data=raw).get_memory_mapped_image();rows=[]
for name in ['original','demura_address_only','display_address','missing_display_label','cached','demura_label_alias','empty_table']:
 u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.mem_map(0,(len(image)+4095)&~4095);u.mem_write(0,image)
 u.mem_map(0x30000000,0x10000);u.mem_map(0x10000000,0x1000)
 u.reg_write(UC_ARM64_REG_SP,0x3000f000);u.reg_write(UC_ARM64_REG_LR,0x10000000);u.reg_write(UC_ARM64_REG_CPACR_EL1,3<<20)
 if name=='demura_address_only':u.mem_write(0x13298+32,(0xc1000000).to_bytes(8,'little'))
 if name=='display_address':u.mem_write(0x136d0+32,(0xc2000000).to_bytes(8,'little'))
 if name=='missing_display_label':u.mem_write(0x136d0,b'x')
 if name=='cached':u.mem_write(0x14986,b'\x01')
 if name=='demura_label_alias':u.mem_write(0x13298,b'Display Reserved\0'+bytes(15))
 if name=='empty_table':u.mem_write(0x13010+40,bytes(8))
 def hook(cpu,pc,n,arg):
  if pc==0x1f04:raise AssertionError('original ASSERT reached')
 u.hook_add(UC_HOOK_CODE,hook);u.emu_start(0x1cf8,0x10000000,count=200000)
 assert u.reg_read(UC_ARM64_REG_PC)==0x10000000
 status=u.reg_read(UC_ARM64_REG_X0);chosen=int.from_bytes(u.mem_read(0x14bc0,8),'little');second=int.from_bytes(u.mem_read(0x14ab8,8),'little')
 if name in ['missing_display_label','empty_table']:assert status==0x800000000000000e and chosen==0
 elif name=='cached':assert status==0 and chosen==0
 else:
  expected={'original':0xb8000000,'demura_address_only':0xb8000000,'display_address':0xc2000000,'demura_label_alias':0xa2a80000}[name]
  assert status==0 and chosen==expected and second==expected+2440*2268*4
 rows.append({'case':name,'controlled_data_mutation':name!='original','status':hex(status),'selected_base':hex(chosen),'second_buffer':hex(second)})
x={'passed':True,'cases':len(rows),'installed_PE_sha256':identity,'original_function':'0x1cf8','original_helpers_executed':True,'native_operations':0,
   'frame_bytes':2440*2268*4,'double_UI_buffer_fits_Display_Reserved':2440*2268*4*2<=0x2b00000,
   'results':rows,'limits':['This is display UI buffer reservation logic, not a live DPU ownership capture.',
   'The OEM bootloader may have programmed other buffers before this UEFI driver.',
   'No hardware/UEFI initialization or native display operation is executed.']}
a.output.write_text(json.dumps(x,indent=2)+'\n');print(json.dumps({'passed':True,'cases':len(rows),'original_selected_base':rows[0]['selected_base'],'native_operations':0}))
