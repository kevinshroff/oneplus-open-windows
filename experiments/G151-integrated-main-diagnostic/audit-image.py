"""Compare every nested firmware member with G146 and bind the Android payload."""
from pathlib import Path
from importlib.machinery import SourceFileLoader
import ast,collections,gzip,hashlib,json,struct
import pefile
w=Path(__file__).resolve().parent;p=w/'private'
sha=lambda b:hashlib.sha256(b).hexdigest()
m=SourceFileLoader('g106inventory',str(w.parent/'charging-G106/inventory-fd.py')).load_module()
prior_source=(w.parent/'charging-G144/audit-image.py').read_text()
cls=next(n for n in ast.parse(prior_source).body if isinstance(n,ast.ClassDef)and n.name=='Extract')
env={'m':m,'struct':struct};exec(compile(ast.Module(body=[cls],type_ignores=[]),'<inherited-extractor>','exec'),env)
Extract=env['Extract']
old=(w.parent/'charging-G146/private/G146-dtb-auth.fd').read_bytes()
new=(p/'G151-main-auth.fd').read_bytes()
assert len(old)==len(new)==4<<20 and sha(old)=='e1685aee753be631faeee8ba25af9fab74f5d3558e8ea350c46dbaa3a550a2ba'
a,b=Extract(),Extract();a.volume(old);b.volume(new)
assert set(a.raw)==set(b.raw)and len(a.raw)==215 and a.configs==b.configs
ar={x['guid']:x for x in a.files};br={x['guid']:x for x in b.files}
assert all(ar[k]['type']==br[k]['type']and ar[k]['ui_names']==br[k]['ui_names']and ar[k]['section_types']==br[k]['section_types']for k in a.raw)
bds='6d33944a-ec75-4855-a54d-809c75241f6c';container='9e21fd93-9c72-4c15-8c4b-e77f1db2d792'
def codeview_only(x,y):
 if len(x)!=len(y)or x.count(b'RSDS')!=1 or y.count(b'RSDS')!=1:return False
 n=x.index(b'RSDS')
 if y.index(b'RSDS')!=n:return False
 xx,yy=bytearray(x),bytearray(y);xx[n+4:n+20]=yy[n+4:n+20]=bytes(16)
 if x[19]&0x40:xx[17]=yy[17]=0
 return xx==yy
changes=[];unexpected=[]
for k in a.raw:
 x,y=a.raw[k],b.raw[k]
 if x==y:continue
 if k==bds:reason='Intended G151 DTB/main adapter, exact main payload/admission and explicit error-image binding; compiled flow audit pending'
 elif k==container:reason='LZMA container for independently compared members'
 elif codeview_only(x,y):reason='Only CodeView GUID and derived FFS checksum'
 else:reason='UNEXPLAINED';unexpected.append(k)
 changes.append({'guid':k,'names':br[k]['ui_names'],'reason':reason,'old_bytes':len(x),'new_bytes':len(y),'old_sha256':sha(x),'new_sha256':sha(y)})
pes=[x for kind,x in b.leaves[bds]if kind==0x10];assert len(pes)==1;pe=pes[0]
assert pefile.PE(data=pe).FILE_HEADER.Machine==0xaa64
for marker in [b'OPEN-ADSP-PREFLIGHT G151 version=1',b'DSP_start=dtb_then_main_auth_diagnostic',b'G151_DTB_request base=9E980000',b'G146_DTB_check index=',b'G150_main_check index=',b'G151_public_returns DTB=',b'PRE_POST_direct=not_observed',b'global_DMA=not_proved',b'G151_FINAL',b'G151DSP1',b'G151SIP1',b'G151_SCM_log_publication',b'G144_setup_footprint ready=',b'OPEN-PIL-INVENTORY G139 version=1',b'G128META',b'PAS_allowed=0']:
 assert marker in pe,marker
capture=json.loads((w.parent/'charging-G118/private/firmware-input/capture.json').read_text())
hashes=collections.Counter((x['Bytes'],x['SHA256'])for x in capture['files'])
for(n,h),count in hashes.items():assert pe.count(struct.pack('<Q',n)+bytes.fromhex(h))>=count
assert bytes.fromhex('f71892ad4ff2ac1100a07f63b4a5ef246749a95937a797d50480e7c70b1b2f94')in pe
ids=json.loads((w.parent/'charging-G128/private/bindings-01/identities.json').read_text())
for x in ids['images']:assert bytes.fromhex(x['text_sha256'])in pe
for x in ids['metadata']:assert bytes.fromhex(x['sha256'])in pe and bytes.fromhex(x['config_sha256'])in pe
image=(p/'boot-G151-main-auth.img').read_bytes();old_image=(w.parent/'charging-G146/private/boot-G146-dtb-auth.img').read_bytes()
assert image[:8]==b'ANDROID!'and struct.unpack_from('<I',image,40)[0]==3 and struct.unpack_from('<I',image,12)[0]==0
assert image[:8]+bytes(4)+image[12:4096]==old_image[:8]+bytes(4)+old_image[12:4096]
n=struct.unpack_from('<I',image,8)[0];kernel=gzip.decompress(image[4096:4096+n])
assert sha(old_image)=='02ccf8aad5f4df3ee12311bcf2842a04379ea9f89c0e648d552e8e91796efd03'
old_n=struct.unpack_from('<I',old_image,8)[0]
old_kernel=gzip.decompress(old_image[4096:4096+old_n])
assert kernel[112:]==new and kernel[:112]==old_kernel[:112]
report={'passed':not unexpected,'FD_sha256':sha(new),'image_sha256':sha(image),'image_bytes':len(image),'BDS_sha256':sha(pe),'included_FFS_files':215,'byte_identical_FFS_files':215-len(changes),'changes':changes,'unexpected':unexpected,'G146_configs_byte_identical':True,'G146_memory_maps_unchanged':True,'Android_header_only_kernel_size_changed':True,'bootshim_identical':True,'AUTO':'empty','native_phone_operations':0,'compiled_request':'DTB original public completion followed by main1 INIT/MEM_SETUP/copy/AUTH/original POST; finite admission and exact hashes; no retry/shutdown; native execution pending','limits':['Static build/member comparison, not a native success.','Known CPU/display checks do not prove global DMA ownership or a production power lease.']}
(p/'image-audit.json').write_text(json.dumps(report,indent=2)+'\n');(p/'BdsDxe-linked.efi').write_bytes(pe)
assert not unexpected,unexpected
print(json.dumps({k:v for k,v in report.items()if k not in ['changes','limits']},indent=2))
