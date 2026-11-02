"""Compiled ARM64 ABI checks. Firmware/hardware API boundaries are modeled."""
from pathlib import Path
import json,hashlib,struct
import pefile
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn.arm64_const import UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3,UC_ARM64_REG_LR,UC_ARM64_REG_PC,UC_ARM64_REG_SP
w=Path(__file__).resolve().parent;p=w/'private';base=0x10000000;data=0x90000000;stop=data+0x200
def setup(name):
 b=(p/name).read_bytes();pe=pefile.PE(data=b);u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);image=pe.get_memory_mapped_image();u.mem_map(base,(len(image)+4095)&~4095);u.mem_write(base,image);u.mem_map(data,0x20000);u.reg_write(UC_ARM64_REG_SP,data+0x1f000);u.reg_write(UC_ARM64_REG_LR,stop);return u,hashlib.sha256(b).hexdigest()
rows=[]
u,h=setup('ResetRuntimeDxe.efi');bs=data+0x1000;pmic=data+0x2000;locate=data+0x100;write=data+0x104
u.mem_write(base+0x71b0,struct.pack('<Q',bs));u.mem_write(bs+0x140,struct.pack('<Q',locate));u.mem_write(pmic+0x28,struct.pack('<Q',write));calls=[]
def vendor_hook(uc,at,n,x):
 if at==locate:
  assert bytes(uc.mem_read(uc.reg_read(UC_ARM64_REG_X0),16)).hex()=='665ba49ba4ef1c44a3e4ed2224786be2'
  assert uc.reg_read(UC_ARM64_REG_X1)==0;uc.mem_write(uc.reg_read(UC_ARM64_REG_X2),struct.pack('<Q',pmic));uc.reg_write(UC_ARM64_REG_X0,0);uc.reg_write(UC_ARM64_REG_PC,uc.reg_read(UC_ARM64_REG_LR))
 if at==write:
  args=[uc.reg_read(r)for r in [UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3]];assert args==[0,3,4,254],args;calls.append(args);uc.reg_write(UC_ARM64_REG_X0,0);uc.reg_write(UC_ARM64_REG_PC,uc.reg_read(UC_ARM64_REG_LR))
u.hook_add(UC_HOOK_CODE,vendor_hook);u.reg_write(UC_ARM64_REG_X0,2);u.emu_start(base+0x2c68,stop,count=10000);assert u.reg_read(UC_ARM64_REG_PC)==stop and u.reg_read(UC_ARM64_REG_X0)==0 and calls==[[0,3,4,254]]
rows.append({'compiled':'ResetRuntimeDxe','sha256':h,'input_reason':2,'modeled_Pmic_WriteSpare_args':calls[0],'native_PMIC_writes':0})
u,h=setup('ABL-f536d559-459f-48fa-8bbc-43b554ecae8d-0.efi');rt=data+0x1000;reset=data+0x108;u.mem_write(base+0xf17a0,struct.pack('<Q',rt));u.mem_write(rt+0x68,struct.pack('<Q',reset));request=[]
def abl_hook(uc,at,n,x):
 if at==base+0x19c98:uc.reg_write(UC_ARM64_REG_PC,uc.reg_read(UC_ARM64_REG_LR))
 if at==reset:
  args=[uc.reg_read(r)for r in [UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3]];buf=bytes(uc.mem_read(args[3],25));assert args[:3]==[0,0x8000000000000002,25];assert buf=='RESET_PARAM\0'.encode('utf-16le')+b'\x02';request.append({'reset_type':args[0],'status':hex(args[1]),'bytes':args[2],'data_hex':buf.hex()});uc.emu_stop()
u.hook_add(UC_HOOK_CODE,abl_hook);u.reg_write(UC_ARM64_REG_X0,2);u.emu_start(base+0x25bc0,stop,count=100000);assert len(request)==1
rows.append({'compiled':'stock-backup ABL; not yet a current native ABL capture','sha256':h,'request':request[0],'modeled_boundaries':['pre-reset helper at0x19c98','ResetSystem'],'native_resets':0})
r={'passed':True,'cases':2,'results':rows,'limitations':['The original firmware instructions execute on modeled RAM/CPU. The firmware LocateProtocol, PMIC WriteSpare, ABL pre-reset hook, and ResetSystem boundaries are modeled; no native PMIC or reset operation is established by this replay.','The current native ABL version has not been captured/bound. The native fastboot outcome remains to be tested.']};(p/'reset-ABI-replay.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r,indent=2))
