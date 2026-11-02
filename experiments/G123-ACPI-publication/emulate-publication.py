"""Execute original ACPI publisher -> table installer bytes with modeled UEFI services."""
from pathlib import Path
import argparse,hashlib,json,struct,uuid
import pefile
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn.arm64_const import UC_ARM64_REG_X0,UC_ARM64_REG_X30,UC_ARM64_REG_SP,UC_ARM64_REG_PC
ap=argparse.ArgumentParser(description=__doc__)
for n in ['publisher','installer','tables','publisher-evidence','installer-evidence','output']:ap.add_argument('--'+n,type=Path,required=True)
a=ap.parse_args();assert not a.output.exists()
raw1=a.publisher.read_bytes();raw2=a.installer.read_bytes();sha=lambda b:hashlib.sha256(b).hexdigest()
assert sha(raw1)=='fe7b75165fd749832a4c030b9094a9288d3cb847b0a804d27d59195a131af981'
assert sha(raw2)=='aecfc4a633301eec241083c2164c6d7f24a7cc73f84f4ad99cc17e63b8d48060'
def observed_bytes(path,address,n):
 def walk(x):
  if isinstance(x,dict):
   r=x.get('normalized_result',{})
   if isinstance(r,dict)and r.get('address')==address and r.get('returned_bytes')==n:return bytes.fromhex(r['bytes_hex'])
   for v in x.values():
    z=walk(v)
    if z is not None:return z
  elif isinstance(x,list):
   for v in x:
    z=walk(v)
    if z is not None:return z
 return walk(json.loads(path.read_text()))
for p,raw,addr,n in [(a.publisher_evidence,raw1,0x1050,1012),(a.installer_evidence,raw2,0x2b54,1848),(a.installer_evidence,raw2,0x5358,248)]:assert observed_bytes(p,hex(addr),n)==pefile.PE(data=raw).get_data(addr,n)
source={p.stem:p.read_bytes()for p in a.tables.glob('*.bin')}
assert sha(source['IORT'])=='56a7577b86c346d5a9467ec14da1304daf0b04c48500de0782fc5479ca67f28a'
assert sha(source['MCFG'])=='7b69ff7edd7a23eaf943a92689f1e568ffdfeb65eb2e7b6e67b3ef3a1947ea41'
B1=0x10000000;B2=0x11000000;DATA=0x20000000;STACK=0x30000000;STUB=0x40000000;END=STUB+0xf00
SYS=DATA+0x1000;BS=DATA+0x2000;FV=DATA+0x3000;HANDLES=DATA+0x4000;CTX=DATA+0x8000;XSDT=DATA+0x9000;RSDP=DATA+0xa000;NOTIFY=DATA+0xb000
ERR=lambda n:(1<<63)|n
class ModelAssert(Exception):pass
rows=[]
def run(name,names,fail=None,notify=False,mutate=False):
 u=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
 for base,n in [(B1,0x10000),(B2,0x10000),(DATA,0x400000),(STACK,0x10000),(STUB,0x1000)]:u.mem_map(base,n)
 for base,raw in [(B1,raw1),(B2,raw2)]:
  pe=pefile.PE(data=raw);pe.relocate_image(base);u.mem_write(base,pe.get_memory_mapped_image())
 u.mem_write(STUB,b'\xc0\x03\x5f\xd6'*1024)
 def q(a):return struct.unpack('<Q',u.mem_read(a,8))[0]
 def wq(a,v):u.mem_write(a,struct.pack('<Q',v))
 def wi(a,v):u.mem_write(a,struct.pack('<I',v))
 def reg(n):return u.reg_read(UC_ARM64_REG_X0+n)
 def ret(v=0):u.reg_write(UC_ARM64_REG_X0,v);u.reg_write(UC_ARM64_REG_PC,u.reg_read(UC_ARM64_REG_X30))
 for off,target in [(0x140,0),(0x138,0x10),(0x98,0x20),(0x48,0x30),(0x40,0x80),(0x28,0x90),(0x30,0xb0),(0xc0,0xa0)]:wq(BS+off,STUB+target)
 wq(SYS+0x58,DATA+0x100);wq(SYS+0x60,BS);wq(B1+0x5e40,DATA+0x200);wq(B2+0xb308,BS);wq(B2+0xb210,20)
 wq(FV+0x10,STUB+0x40);wq(FV+0x18,STUB+0x50);wq(HANDLES,DATA+0x5000)
 wq(CTX,0x45415453);wq(CTX+0x10,RSDP);wq(CTX+0x28,XSDT);wq(CTX+0x78,1);wq(CTX+0x80,1);wq(CTX+0x88,B2+0x2c30)
 for offset in [0x60,0xe8]:wq(CTX+offset,CTX+offset);wq(CTX+offset+8,CTX+offset)
 u.mem_write(XSDT,b'XSDT');wi(XSDT+4,44);u.mem_write(RSDP,b'RSD PTR ');wi(RSDP+20,36);wq(RSDP+24,XSDT)
 if notify:
  wi(NOTIFY,0x4c4e4145);wq(NOTIFY+8,CTX+0xe8);wq(NOTIFY+16,CTX+0xe8);wq(NOTIFY+24,STUB+0xc0);wq(CTX+0xe8,NOTIFY+8);wq(CTX+0xf0,NOTIFY+8)
 heap=DATA+0x10000;allocations={HANDLES:8};allocated_types={};freed=[];calls=[];notified=[];supplied=[];installs=[];assertions=[];bsalloc=0
 def alloc(n,kind,alignment=16):
  nonlocal heap
  heap=(heap+alignment-1)&~(alignment-1);p=heap;heap+=max(n,16);assert heap<DATA+0x400000;allocations[p]=n;allocated_types[p]=kind;u.mem_write(p,bytes(n));return p
 tables=[]
 for sig in names:
  b=source[sig]
  if mutate and sig=='IORT':b=bytearray(b);b[0x4b4]^=1;b=bytes(b)
  tables.append(b)
 def code(uc,pc,n,opaque):
  nonlocal bsalloc
  if pc==END:uc.emu_stop();return
  if pc==B1+0x1444:ret();return # Unrelated entry constructor, explicitly modeled.
  if pc in [B1+0x1628,B2+0x1e3c]:assertions.append(hex(pc));raise ModelAssert('original DEBUG assertion')
  if pc in [B1+0x159c,B2+0x1d8c]:ret();return # Debug output only.
  if pc==STUB:
   calls.append('locate-ACPI-protocol')
   if fail=='locate':ret(ERR(14));return
   assert bytes(uc.mem_read(reg(0),16))==uuid.UUID('ffe06bdd-6107-46a6-7bb2-5a9c7ec5275c').bytes_le
   wq(reg(2),CTX+0x88);ret();return
  if pc==STUB+0x10:
   calls.append('locate-FV-handles')
   if fail=='locate-FV':ret(ERR(14));return
   wq(reg(3),1);wq(reg(4),HANDLES);ret();return
  if pc==STUB+0x20:assert reg(0)==DATA+0x5000;wq(reg(2),FV);ret();return
  if pc==STUB+0x30:
   p=reg(0);assert p in allocations and p not in freed,(hex(p),allocations);freed.append(p);uc.mem_write(p,b'\xdd'*allocations[p]);ret();return
  if pc==STUB+0x40:
   calls.append('FV-file-present');ret(ERR(14)if fail=='FV-file'else 0);return
  if pc==STUB+0x50:
   index=reg(3);calls.append('FV-section-'+str(index));assert reg(2)==0x19
   if index>=len(tables):ret(ERR(14));return
   if fail=='read-first':ret(ERR(7));return
   b=tables[index];p=alloc(len(b),'FV-section');uc.mem_write(p,b);wq(reg(4),p);wq(reg(5),len(b)-(1 if fail=='short'else 0));wi(reg(6),0);supplied.append((p,b));ret();return
  if pc==B2+0x2c30:
   b=bytes(uc.mem_read(reg(1),reg(2)));installs.append({'signature':b[:4].decode(),'input_sha256':sha(b),'bytes':len(b)})
   if fail=='install':ret(ERR(7));return
   # Otherwise execute original InstallAcpiTable/AddTable/Publish/Notify.
  if pc==STUB+0x80:
   bsalloc+=1
   if fail=='table-alloc'and bsalloc==3:ret(ERR(9));return
   p=alloc(reg(1),'UEFI-pool-type'+str(reg(0)));wq(reg(2),p);ret();return
  if pc==STUB+0x90:
   assert reg(0)==1 and reg(1)==10;p=alloc(reg(2)*4096,'ACPI-NVS-pages',4096);wq(reg(3),p);ret();return
  if pc==STUB+0xb0:
   p=reg(0);assert p in allocations;freed.append(p);uc.mem_write(p,b'\xdd'*allocations[p]);ret();return
  if pc==STUB+0xa0:
   calls.append('publish-ACPI2-root');assert reg(1)==RSDP
   ret(ERR(7)if fail=='publish'else 0);return
  if pc==STUB+0xc0:
   p=reg(0);sig=bytes(uc.mem_read(p,4)).decode();assert reg(1)==0x20;notified.append(sig)
   if sig=='IORT':
    # This explicit test callback demonstrates mutability, not a real callback.
    b=bytearray(uc.mem_read(p,struct.unpack('<I',uc.mem_read(p+4,4))[0]));b[0x4b4]^=1;b[9]=0;b[9]=(-sum(b))&255;uc.mem_write(p,bytes(b))
   ret();return
 u.hook_add(UC_HOOK_CODE,code);u.reg_write(UC_ARM64_REG_X0,DATA+0x6000);u.reg_write(UC_ARM64_REG_X0+1,SYS);u.reg_write(UC_ARM64_REG_SP,STACK+0xf000);u.reg_write(UC_ARM64_REG_X30,END)
 stopped=False
 try:u.emu_start(B1+0x1050,END+4,count=5000000)
 except ModelAssert:stopped=True
 except Exception as ex:raise RuntimeError((name,str(ex),hex(u.reg_read(UC_ARM64_REG_PC)),calls[-12:]))from ex
 if not stopped:assert u.reg_read(UC_ARM64_REG_PC)==END,(name,hex(u.reg_read(UC_ARM64_REG_PC)))
 published={};cur=q(CTX+0x60)
 for _ in range(30):
  if cur==CTX+0x60:break
  node=cur-8;p=q(node+32);n=q(node+40);b=bytes(u.mem_read(p,n));published.setdefault(b[:4].decode(),[]).append((p,b));cur=q(cur)
 else:raise AssertionError('list did not close')
 for sig in ['IORT','MCFG']:
  if sig not in published:continue
  for i,(ptr,b)in enumerate(published[sig]):
   original=next(x for x in tables if x[:4].decode()==sig)
   want=bytearray(original);want[9]=0;want[9]=(-sum(want))&255
   if notify and sig=='IORT':want[0x4b4]^=1;want[9]=0;want[9]=(-sum(want))&255
   assert b==want,(name,sig,[i for i,(x,y)in enumerate(zip(b,want))if x!=y][:15])
   assert ptr not in freed and sum(b)%256==0
 if fail in ['locate','locate-FV','FV-file','install','table-alloc','publish']:assert u.reg_read(UC_ARM64_REG_X0)==ERR(21)and not stopped,(name,hex(u.reg_read(UC_ARM64_REG_X0)))
 elif fail=='short':assert stopped and not installs
 else:assert not stopped and u.reg_read(UC_ARM64_REG_X0)==0
 if fail=='read-first':assert not installs and not published
 if not fail:assert len(installs)==len(tables)
 rows.append({'case':name,'publisher_return':hex(u.reg_read(UC_ARM64_REG_X0))if not stopped else None,'DEBUG_assertion_observed':stopped,'installer_calls':len(installs),'published_signatures':list(published),'notifier_callbacks':notified,'IORT_body_preserved_except_checksum':not notify if 'IORT'in published else None,'IORT_output_sha256':sha(published['IORT'][0][1])if'IORT'in published else None,'MCFG_output_sha256':sha(published['MCFG'][0][1])if'MCFG'in published else None,'FACS_changed_offsets_from_input':[i for i,(x,y)in enumerate(zip(published['FACS'][0][1],next(t for t in tables if t[:4]==b'FACS')))if x!=y]if'FACS'in published else None,'freed_buffers_poisoned':len(freed),'UEFI_pool_allocations':bsalloc,'native_operations':0})
run('IORT',['IORT']);run('MCFG-IORT',['MCFG','IORT']);run('all12',['APIC','CSRT','DBG2','FACS','FACP','GTDT','IORT','MCFG','PPTT','SPCR','DSDT','SSDT'])
run('mutated-IORT-input',['IORT'],mutate=True);run('explicit-test-notifier-can-change-copy',['IORT'],notify=True)
for f in ['locate','locate-FV','FV-file','read-first','short','install','table-alloc','publish']:run(f,['IORT'],fail=f)
v={'passed':True,'cases':rows,'publisher_PE_SHA256':sha(raw1),'installer_PE_SHA256':sha(raw2),'REA_body_bytes_match':True,'original_functions_executed':['publisher entry1050..1443 and checksum helper','InstallAcpiTable2c30','AddTableToList2d48','PublishTables2b54','SdtNotifyAcpiList5358','original memory copy/checksum/list helpers'],'modeled':['entry constructor/HOB-list state','ACPI instance constructor state, XSDT/RSDP and notify-list membership','UEFI firmware-volume access, allocation/free and configuration-table publication','debug-output service','optional explicit mutation notifier'],'limits':['No native firmware executes and no actual callback roster is established.','Empty-list publication preserves IORT bytes except checksum; this is not proof of the final Windows table or absence of later mutation.','The explicit test notifier is modeled; it does not show any real client changes IORT.','No interpretation or repair of high0x8703 input bases is validated.'],'source_table_hashes':{n:sha(b)for n,b in source.items()},'native_operations':0}
a.output.write_text(json.dumps(v,indent=2)+'\n');print(json.dumps({'passed':True,'cases':len(rows),'IORT_published_SHA256':rows[0]['IORT_output_sha256'],'MCFG_published_SHA256':rows[1]['MCFG_output_sha256'],'native_operations':0}))
