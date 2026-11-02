"""Replace only the ACPI owner publisher in actual ABI7 combined firmware. Offline."""
from pathlib import Path
import ast,types,struct,uuid,gzip,lzma,json,hashlib,subprocess
H=Path(__file__).resolve().parent;R=H.parents[1];O=H/'candidate';O.mkdir(exist_ok=True);T=R/'work/firmware-build-G203/source/MU_BASECORE/BaseTools/Source/C/bin';sha=lambda b:hashlib.sha256(b).hexdigest();align=lambda n,a=8:(n+a-1)&~(a-1)
def run(args):
 p=subprocess.run(list(map(str,args)),capture_output=True,text=True);assert p.returncode==0,(p.stdout[-2000:],p.stderr[-2000:]);return p.stdout
# Reuse only the frozen structural parser definitions, never its producer.
m=types.ModuleType('inventory');exec(compile((R/'work/charging-G106/inventory-fd.py').read_text(),'<inventory>','exec'),m.__dict__)
a=ast.parse((R/'work/charging-G144/audit-image.py').read_text());cl=next(n for n in a.body if isinstance(n,ast.ClassDef) and n.name=='Extract');env={'m':m,'struct':struct};exec(compile(ast.Module(body=[cl],type_ignores=[]),'<extractor>','exec'),env)
class Capture(env['Extract']):
 def __init__(self):super().__init__();self.blobs={}
 def volume(self,data,path='FD',depth=0):self.blobs[path]=bytes(data);super().volume(data,path,depth)
a=ast.parse((R/'work/wifi-gpu-combined-abi7/package.py').read_text());fun=next(n for n in a.body if isinstance(n,ast.FunctionDef) and n.name=='all_files');env={'struct':struct,'uuid':uuid,'align':align,'sha':sha};exec(compile(ast.Module(body=[fun],type_ignores=[]),'<fv-parser>','exec'),env);all_files=env['all_files']
B=R/'work/wifi-gpu-combined-abi7/candidate';fd=(B/'G736r2-WifiAbi7-combined.fd').read_bytes();image=(B/'boot-G736r2-WifiAbi7-combined.img').read_bytes();assert sha(image)=='8c3ba312d06b8b515617677a0f37da5ba5999d9f198e7a93f099653f579b20c0';assert len(fd)==0x400000
EFI=H/'firmware/Build/OpenGpuOwner/DEBUG_CLANGPDB/AARCH64/OpenOwnerPkg/Publish/OUTPUT';efi=(EFI/'OpenGpuOwnerTables.efi').read_bytes();depex=(EFI/'OpenGpuOwnerTables.depex').read_bytes();assert efi[:2]==b'MZ' and depex[-1]==8
for name,data in [('OpenGpuOwnerTables-G991.efi',efi),('OpenGpuOwnerTables-G991.depex',depex)]:(O/name).write_bytes(data)
run([T/'GenSec','-s','EFI_SECTION_DXE_DEPEX','-o',O/'depex.sec',O/'OpenGpuOwnerTables-G991.depex']);run([T/'GenSec','-s','EFI_SECTION_PE32','-o',O/'pe32.sec',O/'OpenGpuOwnerTables-G991.efi']);run([T/'GenSec','-s','EFI_SECTION_USER_INTERFACE','-n','OpenGpuOwnerTables','-o',O/'ui.sec'])
GUID='ce4ed4f2-f892-40cd-a8d0-0515d0010001';CONTAINER='9e21fd93-9c72-4c15-8c4b-e77f1db2d792';run([T/'GenFfs','-t','EFI_FV_FILETYPE_DRIVER','-g',GUID,'-s','-o',O/'OpenGpuOwnerTables-G991.ffs','-i',O/'depex.sec','-i',O/'pe32.sec','-i',O/'ui.sec']);raw=(O/'OpenGpuOwnerTables-G991.ffs').read_bytes()
base=Capture();base.volume(fd);path=next(k for k in base.blobs if k!='FD');assert len(base.blobs)==2;oldfv=base.blobs[path];rows,used,erase,blocks=all_files(oldfv);assert erase==255
old=next(r for r in rows if r['guid']==GUID);assert raw!=old['raw'];stored=bytearray(raw);stored[23]^=erase
# Rebuild only the child-file sequence, preserving all other raw files exactly.
head=struct.unpack_from('<H',oldfv,48)[0];body=bytearray(oldfv[:align(head)])
for r in rows:
 data=stored if r['guid']==GUID else r['raw'];body.extend(data);body.extend(bytes([erase])*(align(len(body))-len(body)))
length=max(len(oldfv),align(len(body),4096));assert length<0xffffff-8;body.extend(bytes([erase])*(length-len(body)));struct.pack_into('<Q',body,32,length);struct.pack_into('<I',body,56,length//4096);struct.pack_into('<H',body,50,0);struct.pack_into('<H',body,50,(-sum(struct.unpack('<36H',body[:72])))&65535)
newrows,*_=all_files(body);assert [r['guid'] for r in newrows]==[r['guid'] for r in rows]
for oldr,newr in zip(rows,newrows):
 if oldr['guid']!=GUID:assert oldr['raw']==newr['raw']
outer,_,oe,_=all_files(fd);parent=next(r for r in outer if r['guid']==CONTAINER);assert parent==outer[-1];rh=parent['raw'];section=rh[24:];offset,attrs=struct.unpack_from('<HH',section,20);assert offset==24 and attrs==1
expanded=lzma.decompress(section[offset:],format=lzma.FORMAT_ALONE);assert expanded[8:]==oldfv and expanded[7]==0x17;stream=bytearray(expanded[:8])+body;stream[4:7]=(len(body)+4).to_bytes(3,'little');(O/'FVMAIN.sections').write_bytes(stream);run([T/'LzmaCompress','-e','-o',O/'FVMAIN.lzma',O/'FVMAIN.sections']);compressed=(O/'FVMAIN.lzma').read_bytes();assert lzma.decompress(compressed,format=lzma.FORMAT_ALONE)==stream
sec=bytearray(section[:offset])+compressed;sec[:3]=len(sec).to_bytes(3,'little');hdr=bytearray(rh[:24]);hdr[20:23]=(24+len(sec)).to_bytes(3,'little');hdr[17]=(-sum(sec))&255 if hdr[19]&0x40 else 0xaa;hdr[16]=0;hdr[16]=(-(sum(hdr)-hdr[17]-hdr[23]))&255
newparent=hdr+sec;assert parent['offset']+len(newparent)<=len(fd);candidate=bytearray(fd);candidate[parent['offset']:]=bytes([oe])*(len(fd)-parent['offset']);candidate[parent['offset']:parent['offset']+len(newparent)]=newparent;candidate=bytes(candidate)
chk=Capture();chk.volume(candidate);assert set(chk.raw)==set(base.raw);changed=[g for g in base.raw if chk.raw[g]!=base.raw[g]];assert set(changed)=={GUID,CONTAINER},changed
for b in chk.blobs.values():all_files(b)
assert image[:8]==b'ANDROID!' and struct.unpack_from('<I',image,40)[0]==3;oldn=struct.unpack_from('<I',image,8)[0];kernel=gzip.decompress(image[4096:4096+oldn]);assert kernel[112:]==fd;gz=gzip.compress(kernel[:112]+candidate,mtime=0);header=bytearray(image[:4096]);struct.pack_into('<I',header,8,len(gz));boot=bytes(header)+gz;boot+=bytes(align(len(boot),4096)-len(boot));assert gzip.decompress(boot[4096:4096+len(gz)])[112:]==candidate;assert boot[:8]+bytes(4)+boot[12:4096]==image[:8]+bytes(4)+image[12:4096]
(O/'G991-CP-IRQ709-combined.fd').write_bytes(candidate);(O/'boot-G991-CP-IRQ709-combined.img').write_bytes(boot)
report={'offline_only':True,'staged_or_booted':False,'base_image_sha256':sha(image),'base_fd_sha256':sha(fd),'candidate_fd_sha256':sha(candidate),'image_sha256':sha(boot),'image_bytes':len(boot),'publisher_EFI_sha256':sha(efi),'publisher_FFS_sha256':sha(raw),'changed_raw_FFS':changed,'all_other_raw_FFS_exact':True,'raw_FFS_count':len(base.raw),'old_publisher_bytes':len(old['raw']),'new_publisher_bytes':len(raw),'WLAN_DXE_exact':chk.raw['82f10622-a583-4e53-87da-2d41b22aa622']==base.raw['82f10622-a583-4e53-87da-2d41b22aa622'],'bootstrap_exact':chk.raw['dcbbd052-7874-4c34-9421-891fc95a0150']==base.raw['dcbbd052-7874-4c34-9421-891fc95a0150'],'boot_and_LZMA_roundtrips_pass':True,'requires_matching_new_driver_pair':True}
(H/'PACKAGE-VERIFIED.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
