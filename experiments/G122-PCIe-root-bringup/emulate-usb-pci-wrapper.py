"""Run the actual installed USB PCI-emulation start routine with modeled services."""
from pathlib import Path
import argparse,hashlib,json,struct,uuid
import pefile
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_MEM_READ,UC_HOOK_MEM_WRITE
from unicorn.arm64_const import UC_ARM64_REG_X0,UC_ARM64_REG_X30,UC_ARM64_REG_SP,UC_ARM64_REG_PC
w=Path(__file__).resolve().parent;ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--binary',type=Path,required=True);ap.add_argument('--REA-evidence',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);args=ap.parse_args();assert not args.output.exists();p=args.binary;raw=p.read_bytes();assert hashlib.sha256(raw).hexdigest()=='e5a7415340b61e7aeefc5c2d8a3b2b24b5bd843b3a1e0138d55ee287567fa862'
# Bind original executed bytes to the provider's independently returned body.
e=json.loads(args.REA_evidence.read_text())
def findbyte(x):
 if isinstance(x,dict):
  nr=x.get('normalized_result',{})
  if isinstance(nr,dict)and nr.get('address')=='0x155c'and nr.get('returned_bytes')==948:return nr['bytes_hex']
  for v in x.values():
   r=findbyte(v)
   if r:return r
 elif isinstance(x,list):
  for v in x:
   r=findbyte(v)
   if r:return r
assert bytes.fromhex(findbyte(e))==raw[0x155c:0x1910]
BASE=0x10000000;DATA=0x20000000;STACK=0x30000000;USB=0x50000000;STUB=0x60000000;RETURN=STUB+0xf00
BS=DATA;PROTO=DATA+0x1000;THIS=DATA+0x2000;CONTROLLER=DATA+0x3000;PRIV=DATA+0x4000;CONFIG=DATA+0x5000
ERR=(1<<63)|7
cases=[]
def run(fail=None,ports=0,install_error=False,port_value=0):
 pe=pefile.PE(data=raw);pe.relocate_image(BASE);image=pe.get_memory_mapped_image();u=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
 for addr,n in [(BASE,0x10000),(DATA,0x10000),(STACK,0x10000),(USB,0x10000),(STUB,0x1000)]:u.mem_map(addr,n)
 u.mem_write(BASE,image);u.mem_write(STUB,b'\xc0\x03\x5f\xd6'*1024)
 def put64(a,v):u.mem_write(a,struct.pack('<Q',v))
 def get64(a):return struct.unpack('<Q',u.mem_read(a,8))[0]
 def put32(a,v):u.mem_write(a,struct.pack('<I',v))
 put64(BASE+0x8270,BS);put64(BS+0x118,STUB);put64(BS+0x148,STUB+0x40)
 put64(PROTO+0x10,STUB+0x10);put64(PROTO+0x38,STUB+0x20);put64(PROTO+8,STUB+0x30);put32(PROTO+0x88,0)
 put64(THIS+0x28,DATA+0x8000)
 put32(USB,0x20);put32(USB+4,ports<<24);put32(USB+0x10,8 if ports else 0);put32(USB+0x14,0x1000);put32(USB+0x18,0x2000)
 for i in range(ports):put32(USB+0x420+i*0x10,port_value)
 calls=[];reads=[];writes=[];protocols=[]
 def reg(n):return u.reg_read(UC_ARM64_REG_X0+n)
 def ret(v=0):u.reg_write(UC_ARM64_REG_X0,v);u.reg_write(UC_ARM64_REG_PC,u.reg_read(UC_ARM64_REG_X30))
 def code(uc,a,n,opaque):
  if a==RETURN:uc.emu_stop();return
  if a==STUB:
   assert reg(0)==CONTROLLER
   calls.append('open-USB-config');
   if fail=='open':ret(ERR);return
   put64(reg(2),PROTO);ret();return
  if a==STUB+0x10:
   assert reg(0)==PROTO and reg(1)==1 and reg(2)==0;calls.append('configure-USB-host');ret(ERR if fail=='configure'else 0);return
  if a==STUB+0x20:
   assert reg(0)==PROTO and reg(1)==1 and reg(2)==0;calls.append('get-USB-core-type')
   if fail=='type':ret(ERR);return
   put32(reg(3),1);ret();return
  if a==STUB+0x30:
   assert reg(0)==PROTO and reg(1)==1;calls.append('get-USB-core-base')
   if fail=='base':ret(ERR);return
   put64(reg(2),USB);ret();return
  if a==BASE+0x25d0:
   assert reg(0)==0x1a8;calls.append('allocate-private');ret(0 if fail=='private-alloc'else PRIV);return
  if a==BASE+0x2660:
   assert 64<=reg(0)<=4096;calls.append('allocate-config');ret(0 if fail=='config-alloc'else CONFIG);return
  if a==BASE+0x266c:calls.append('free-private');ret();return
  if a==BASE+0x2724:
   dst,src,size=reg(0),reg(1),reg(2);assert size in [10,0xa0];uc.mem_write(dst,bytes(uc.mem_read(src,size)));ret(dst);return
  if a==BASE+0x2bb8:calls.append('debug');ret();return
  if a==STUB+0x40:
   calls.append('install-protocols');assert reg(5)==0
   for i in [1,3]:protocols.append({'GUID':str(uuid.UUID(bytes_le=bytes(uc.mem_read(reg(i),16)))),'interface':reg(i+1)})
   ret(ERR if install_error else 0);return
 def memory(uc,access,a,n,v,opaque):
  if USB<=a<USB+0x10000:
   if access==16:reads.append([hex(a-USB),n])
   else:writes.append([hex(a-USB),n,v])
 u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_READ|UC_HOOK_MEM_WRITE,memory)
 u.reg_write(UC_ARM64_REG_X0,THIS);u.reg_write(UC_ARM64_REG_X0+1,CONTROLLER);u.reg_write(UC_ARM64_REG_SP,STACK+0xf000);u.reg_write(UC_ARM64_REG_X30,RETURN)
 u.emu_start(BASE+0x155c,RETURN+4,count=15000);assert u.reg_read(UC_ARM64_REG_PC)==RETURN
 if fail in ['open','configure','type','base']:assert u.reg_read(UC_ARM64_REG_X0)==ERR and not reads and not writes and not protocols
 if fail in ['private-alloc','config-alloc']:assert u.reg_read(UC_ARM64_REG_X0)==(1<<63)|9 and not protocols
 if fail is None:
  assert protocols==[{'GUID':'4cf5b200-68b8-4ca5-9eec-b23e3f50029a','interface':PRIV+16},{'GUID':'09576e91-6d3f-11d2-8e39-00a0c969723b','interface':PRIV+4}],protocols
  assert bytes(u.mem_read(CONFIG,4))==bytes.fromhex('43510201')
  assert bytes(u.mem_read(CONFIG+9,3))==bytes.fromhex('30030c')
  assert reads==[['0x0',1],['0x4',4],['0x10',4],['0x14',4],['0x18',4]]+[[hex(0x420+i*16),4]for i in range(ports)] and writes==[[hex(0x420+i*16),4,port_value|512]for i in range(ports)],(reads,writes)
  assert u.reg_read(UC_ARM64_REG_X0)==(ERR if install_error else 0)
 row={'case':fail or('install-error'if install_error else f'USB-success-ports{ports}-initial{port_value:x}'),'services':calls,'modeled_USB_reads':reads,'modeled_USB_writes':writes,'protocol_GUIDs_submitted':[x['GUID']for x in protocols],'result':hex(u.reg_read(UC_ARM64_REG_X0)),'synthetic_PCI_vendor_device':bytes(u.mem_read(CONFIG,4)).hex()if protocols else None};cases.append(row)
for f in ['open','configure','private-alloc','type','base','config-alloc']:run(fail=f)
run();run(ports=2);run(ports=2,port_value=0x1000);run(install_error=True)
v={'passed':True,'cases':cases,'original_ARM64_body_executed':'0x155c..0x190f','body_bytes_match_REA':True,'PE_sha256':hashlib.sha256(raw).hexdigest(),'modeled_services':['UEFI OpenProtocol and InstallMultipleProtocolInterfaces','USB Config interface','allocation, free, memcpy and debug helpers','USB register RAM and return sentinel'],'executed_original_helpers':['8-bit MMIO read 2dc4','32-bit MMIO read 2e14','32-bit MMIO read/OR/write 2d94'],'limits':['This proves only the tested driver-binding Start paths with explicit model services.','No native firmware dispatch, physical USB operation or complete absence of PCIe initialization elsewhere is established.','UEFI PCI I/O emulation is distinct from the hardware PCIe root-complex protocol.'],'native_operations':0}
args.output.write_text(json.dumps(v,indent=2)+'\n');print(json.dumps({'passed':True,'cases':len(cases),'synthetic_vendor':'0x5143','synthetic_device':'0x0102','protocols_submitted':['PCI_IO','DEVICE_PATH'],'hardware_PCIe_root_protocol_installed_in_tested_start':False,'native_operations':0}))
