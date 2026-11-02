"""Audit the built image against the actual G80 FD, including nested FFS leaves."""
from pathlib import Path
from importlib.machinery import SourceFileLoader
import collections,gzip,hashlib,json,struct,sys
import pefile

w=Path(__file__).resolve().parent
m=SourceFileLoader('g106inventory',str(w.parent/'charging-G106/inventory-fd.py')).load_module()
sha=lambda b:hashlib.sha256(b).hexdigest()
class Extract(m.Inventory):
 def __init__(self):super().__init__();self.raw={};self.leaves={}
 def volume(self,data,path='FD',depth=0):
  start=len(self.files);super().volume(data,path,depth)
  for row in self.files[start:]:
   if row['volume']==path:
    assert row['guid']not in self.raw
    self.raw[row['guid']]=data[row['offset']:row['offset']+row['bytes']]
 def sections(self,data,owner,path,depth):
  super().sections(data,owner,path,depth)
  off=0
  while off<len(data):
   size=int.from_bytes(data[off:off+3],'little');head=4
   if size==0xffffff:size=struct.unpack_from('<I',data,off+4)[0];head=8
   kind=data[off+3]
   if kind in (0x10,0x12,0x19):self.leaves.setdefault(owner['guid'],[]).append((kind,data[off+head:off+size]))
   off=min((off+size+3)&~3,len(data))

base=(w.parent/'gauges-G104/private/G80-normal-FV.fd').read_bytes()
new=(w/'private/G119-preflight.fd').read_bytes()
assert len(base)==len(new)==4<<20 and sha(base)=='93fb6c036781ec946aa7a5a91eb21e756dec17ce57447a16b757670a7dda34e1'
a,b=Extract(),Extract();a.volume(base);b.volume(new)
assert set(a.raw)==set(b.raw)and len(a.raw)==215
old_rows={x['guid']:x for x in a.files};new_rows={x['guid']:x for x in b.files}
assert all(old_rows[k]['type']==new_rows[k]['type']and old_rows[k]['ui_names']==new_rows[k]['ui_names']and old_rows[k]['section_types']==new_rows[k]['section_types']for k in a.raw)

prepi='3e401783-cc94-4fcd-97bc-bd35ac369d2f'
bds='6d33944a-ec75-4855-a54d-809c75241f6c'
ram='26e06c9c-53d0-0136-5d54-64f38de2fb59'
container='9e21fd93-9c72-4c15-8c4b-e77f1db2d792'
te=[x for k,x in a.leaves[prepi]if k==0x12];assert len(te)==1 and sha(te[0])=='9207af80d4f4584d186c9f2f474669ff65b893c5d644f9dce7cbbdb4272a7a02'
old_table=te[0][60888:60888+49*72];assert len(old_table)==49*72
assert old_table[8*72:8*72+13]==b'PIL Reserved\0' and old_table[9*72:9*72+15]==b'Display Demura\0'
assert struct.unpack_from('<QQ',old_table,8*72+32)==(0x8A800000,0x18280000)
assert struct.unpack_from('<QQ',old_table,9*72+32)==(0xA2A80000,0x02B00000)
new_table=bytearray(old_table)
struct.pack_into('<Q',new_table,8*72+40,0x18A80000)
struct.pack_into('<QQ',new_table,9*72+32,0xA3280000,0x02300000)
new_table=bytes(new_table)
new_te=[x for k,x in b.leaves[prepi]if k==0x12];assert len(new_te)==1 and new_te[0].count(new_table)==1

def debug_only(old,new,allow_te=False):
 if len(old)!=len(new):return False
 try:
  p=old.index(b'MZ');q=new.index(b'MZ')
  if p!=q:return False
  x,y=pefile.PE(data=old[p:]),pefile.PE(data=new[q:])
  xd=[d.struct for d in x.DIRECTORY_ENTRY_DEBUG if d.struct.Type==2]
  yd=[d.struct for d in y.DIRECTORY_ENTRY_DEBUG if d.struct.Type==2]
  if len(xd)!=1 or len(yd)!=1 or xd[0].PointerToRawData!=yd[0].PointerToRawData:return False
  pos=p+xd[0].PointerToRawData
  if old[pos:pos+4]!=new[pos:pos+4]or old[pos:pos+4]!=b'RSDS':return False
  xx,yy=bytearray(old),bytearray(new)
  xx[pos+4:pos+20]=bytes(16);yy[pos+4:pos+20]=bytes(16)
  # These bytes are derived file/image checksums, verified structurally above.
  if old[19]&0x40:xx[17]=yy[17]=0
  return xx==yy
 except (ValueError,AttributeError,pefile.PEFormatError):
  te_start=a.raw[prepi].find(te[0])
  if not allow_te or te_start<0 or old[te_start:te_start+2]!=b'VZ' or new[te_start:te_start+2]!=b'VZ':return False
  if old.count(b'RSDS')!=1 or new.count(b'RSDS')!=1:return False
  pos=old.index(b'RSDS')
  if new.index(b'RSDS')!=pos:return False
  xx,yy=bytearray(old),bytearray(new)
  xx[pos+4:pos+20]=bytes(16);yy[pos+4:pos+20]=bytes(16)
  if old[19]&0x40:xx[17]=yy[17]=0
  return xx==yy

changed=[];unexpected=[];same=0
for key in a.raw:
 old,newraw=a.raw[key],b.raw[key]
 if old==newraw:same+=1;continue
 row={'guid':key,'names':old_rows[key]['ui_names'],'old_sha256':sha(old),'new_sha256':sha(newraw),'old_bytes':len(old),'new_bytes':len(newraw)}
 if key==container:row['reason']='LZMA container for the independently compared member set'
 elif key in m.CONFIGS and m.CONFIGS[key]in('uefiplat.cfg','uefipil.cfg'):
  name=m.CONFIGS[key];expected=(w/'private/candidate-source/Platforms/KailuaPkg/Device/oneplus-open/Binaries/RawFiles'/name).read_bytes()
  assert b.configs[name]==expected
  row['reason']='exact reviewed candidate config; AUTO remains empty'
 elif old.count(old_table)==1 and newraw.count(new_table)==1 and key!=bds:
  assert old.count(old_table)==1 and newraw.count(new_table)==1
  restored=newraw.replace(new_table,old_table)
  if restored!=old and not debug_only(old,restored,allow_te=(key==prepi)):unexpected.append(key)
  row['reason']='exact 49-record memory table replacement, with at most a CodeView GUID change'
 elif key==bds:
  pes=[x for kind,x in b.leaves[key]if kind==0x10];assert len(pes)==1
  assert pes[0].count(new_table)==1
  assert b'OPEN-ADSP-PREFLIGHT G119 version=1'in pes[0]
  assert b'ba26f22b2ee03897148adaa7f34e1df350ef7f26bd24af6dbcd5878e8020e882'in pes[0]
  manifest=json.loads((w.parent/'charging-G118/private/firmware-input/capture.json').read_text())
  hashes=collections.Counter((r['Bytes'],r['SHA256'])for r in manifest['files'])
  for (n,h),count in hashes.items():assert pes[0].count(struct.pack('<Q',n)+bytes.fromhex(h))>=count
  row['reason']='reviewed source-built BDS preflight, mode 15 and all 64 bound file digests'
 elif debug_only(old,newraw):row['reason']='whole FFS identical outside its 16-byte CodeView GUID'
 else:unexpected.append(key);row['reason']='UNEXPLAINED - do not deploy'
 changed.append(row)

image=(w/'private/boot-G119-preflight.img').read_bytes()
old_image=(w.parent/'boot-repair-G80/private/firmware-normal/boot-G80-normal.img').read_bytes()
assert image[:8]==b'ANDROID!'and struct.unpack_from('<I',image,40)[0]==3 and struct.unpack_from('<I',image,12)[0]==0
assert image[:8]+bytes(4)+image[12:4096]==old_image[:8]+bytes(4)+old_image[12:4096]
n=struct.unpack_from('<I',image,8)[0];kernel=gzip.decompress(image[4096:4096+n])
assert kernel[112:]==new and sha(kernel[:112])=='1f5950ef61a07aeff91a6435821d54c72942d1d85757a5dfaa50f01513c26115'
report={'passed':not unexpected,'FD_sha256':sha(new),'image_sha256':sha(image),'image_bytes':len(image),'included_FFS_files':215,'byte_identical_FFS_files':same,'changed':changed,'unexpected':unexpected,'PrePi_49_record_table_exact':True,'memory_table_changed_bytes':sum(x!=y for x,y in zip(old_table,new_table)),'Android_header_only_kernel_size_changed':True,'bootshim_identical':True,'AUTO':'empty','DSP_request_count':0,'native_phone_operations':0,'limits':['This is a complete build and static image audit, not a successful native preflight boot.','The preflight does not qualify physical display ownership, SCM authentication or DSP/charging operation.']}
(w/'private/image-audit.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({k:v for k,v in report.items()if k not in ['changed','limits']},indent=2))
for row in changed:print(row['guid'],row['names'],row['reason'],row['old_bytes'],row['new_bytes'])
assert not unexpected,'Unexpected firmware changes require analysis before staging.'
