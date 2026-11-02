from pathlib import Path
import hashlib,struct,json,subprocess,sys,zlib,uuid
from Registry import Registry
ROOT=Path('/path/to/user/Documents/Codex/2026-10-20/sta');W=ROOT/'work/boot-repair-G80';P=W/'private';S=W/'scripts';E=W/'captures'
sys.path.insert(0,str(ROOT/'work/debug-G08'));from fat32_read import Fat32
sha=lambda b:hashlib.sha256(b).hexdigest()
def registry(p):
 r=Registry.Registry(str(p));out={}
 def walk(k,path=''):
  out[path]={v.name():[v.value_type(),v.value().hex() if isinstance(v.value(),bytes) else v.value()] for v in k.values()}
  for c in k.subkeys():walk(c,path+'/'+c.name())
 walk(r.root());return out
before=registry(ROOT/'work/recovery-G79/private/phone-r5/BCD-original');after=registry(P/'BCD-after')
assert before.keys()<=after.keys()
changed={k for k in before.keys()|after.keys() if before.get(k)!=after.get(k)}
pe='{c94d8c9e-a81c-4de9-968d-ded00f001818}';osid='{a1a2a3a4-b5b6-c7c8-d9da-dbdcdddedfe0}';mgr='{9dea862c-5cdd-4e70-acc1-f32b344d4795}';ram='{ae5534e0-a924-466c-b836-758539a3ee3a}'
allowed={f'/Objects/{obj}/Elements/{t}' for obj,types in [(pe,['11000001','21000001','12000004','26000022','16000010']),(osid,['12000004','26000022','16000010']),(mgr,['23000003','24000001','16000010']),(ram,['31000003'])] for t in types}
allowed.add('/Description')
assert changed<=allowed,changed-allowed
for k in ('','/Objects'):
 assert before[k]==after[k]
assert after[f'/Objects/{mgr}/Elements/23000003']['Element']==[1,pe]
assert after[f'/Objects/{mgr}/Elements/24000001']['Element'][1]==[pe,osid,'',''] or after[f'/Objects/{mgr}/Elements/24000001']['Element'][1]==[pe,osid]
assert after[f'/Objects/{pe}/Elements/26000022']['Element']==[3,'01']
assert after[f'/Objects/{osid}/Elements/26000022']['Element']==[3,'00']
assert f'/Objects/{mgr}/Elements/24000002' not in after
assert before[f'/Objects/{osid}/Elements/11000001']==after[f'/Objects/{osid}/Elements/11000001']
assert before[f'/Objects/{osid}/Elements/21000001']==after[f'/Objects/{osid}/Elements/21000001']
# Metadata differences remain explicit; all other keys/values are byte-preserved.
(E/'bcd-semantic-audit.json').write_text(json.dumps({'result':'pass','before_sha256':sha((ROOT/'work/recovery-G79/private/phone-r5/BCD-original').read_bytes()),'after_sha256':sha((P/'BCD-after').read_bytes()),'changed_keys':sorted(changed),'before_keys':len(before),'after_keys':len(after),'description_before':before['/Description'],'description_after':after['/Description'],'full_OS_device_and_osdevice_unchanged':True,'PE_default_and_displayorder_pinned':True,'unsafe_deploy_entry_not_in_menu':True},indent=2))
img=P/'boot-fat-4kn-1GiB.img'
# Drop stale BCD transaction logs from the new filesystem, then install the clean candidate.
for path in ['::/EFI/Microsoft/Boot/BCD.LOG']:
 
 if path[3:].lower() in {n.lower() for n,_ in Fat32(img).walk()}:
  subprocess.run(['colima','ssh','--','mdel','-i',str(img),path],check=True)
subprocess.run(['colima','ssh','--','mcopy','-o','-i',str(img),str(P/'BCD-after'),'::/EFI/Microsoft/Boot/BCD'],check=True)
f=Fat32(img);manifest={n:{'bytes':len(b),'sha256':sha(b)} for n,b in f.walk()}
manifest={n.lower():m for n,m in manifest.items()}
orig=json.loads((ROOT/'work/recovery-G79/private/phone-r5/fat-files-manifest.json').read_text())
for n,m in orig.items():
 if n in ('EFI/Microsoft/Boot/BCD','EFI/Microsoft/Boot/BCD.LOG'):continue
 assert manifest[n.lower()]==m,n
assert manifest['openg18/g18-maintenance.wim']['sha256']=='a702247a17605e5a66c809bbe4abf6b2c336548cf50dd8936e545fb66bcd1f9f'
assert manifest['efi/microsoft/boot/bcd']['sha256']==sha((P/'BCD-after').read_bytes())
assert f.sector==4096 and f.cluster_sectors==1 and f.total_sectors==262144
assert f.read(f.reserved*f.sector,f.fat_sectors*f.sector)==f.read((f.reserved+f.fat_sectors)*f.sector,f.fat_sectors*f.sector)
(E/'fat-files.json').write_text(json.dumps(manifest,indent=2))
r=subprocess.run(['colima','ssh','--','fsck.fat','-n',str(img)],stdout=subprocess.PIPE,stderr=subprocess.STDOUT);(P/'fat-fsck.log').write_bytes(r.stdout);assert r.returncode==0,r.stdout
old=ROOT/'work/recovery-G79/private/phone-r5/userdata-first1GiB.img';assert old.stat().st_size==img.stat().st_size==1<<30
h0=hashlib.sha256();h1=hashlib.sha256();table=bytearray();changed_chunks=0
with old.open('rb') as a,img.open('rb') as b:
 for i in range(16384):
  x=a.read(65536);y=b.read(65536);assert len(x)==len(y)==65536;h0.update(x);h1.update(y);table+=hashlib.sha256(x).digest()+hashlib.sha256(y).digest();changed_chunks+=x!=y
assert h0.hexdigest()=='aa4caaf24a8443e6ac35ffe6ccb5c825412f0c3811300fd93178f2cdb801c6b9'
header=bytearray(256);header[:8]=b'OP80P01\0';struct.pack_into('<4I2Q',header,8,1,4096,65536,16384,1<<30,64);header[48:80]=h0.digest();header[80:112]=h1.digest()
plan=bytes(header)+table;(P/'G80-pinned-plan.bin').write_bytes(plan)
(S/'OpenPinnedPlanIdentity.h').write_text('STATIC CONST UINT8 mPinnedPlanHash[32] = {'+','.join('0x%02x'%v for v in hashlib.sha256(plan).digest())+'};\n')
proof={'image_bytes':1<<30,'sector_bytes':4096,'cluster_bytes':4096,'fat_copies_identical':True,'fsck_exit':0,'files':len(manifest),'before_sha256':h0.hexdigest(),'after_sha256':h1.hexdigest(),'changed_64KiB_chunks':changed_chunks,'plan_bytes':len(plan),'plan_sha256':sha(plan),'inert_WIM_sha256':manifest['openg18/g18-maintenance.wim']['sha256'],'phone_writes':0}
(E/'fat-plan-preparation.json').write_text(json.dumps(proof,indent=2));print(json.dumps(proof,indent=2))
# Construct exact GPT golden data from the last verified G16 after-state.
base=ROOT/'outputs/bringup-20261020/gpttype-G16-observed/verified-GPT-after';names=['protective-mbr','primary-header','primary-entries','backup-header','backup-entries'];raw=[(base/(n+'.bin')).read_bytes() for n in names];target=[bytearray(v) for v in raw]
assert struct.unpack_from('<II',raw[1],80)==(32,128)
off=13*128;entry=raw[2][off:off+128]
assert str(uuid.UUID(bytes_le=entry[:16]))=='1b81e7e6-f50d-419b-a739-2aeef8da3335' and str(uuid.UUID(bytes_le=entry[16:32]))=='5982c0bf-b83f-025d-4354-68009ba0a5d1'
for i in (2,4):target[i][off:off+16]=uuid.UUID('c12a7328-f81f-11d2-ba4b-00a0c93ec93b').bytes_le
crc=zlib.crc32(target[2]);assert target[2]==target[4]
for i in (1,3):
 struct.pack_into('<I',target[i],88,crc);struct.pack_into('<I',target[i],16,0);struct.pack_into('<I',target[i],16,zlib.crc32(target[i][:92]))
for which,blobs in [('before',raw),('after',target)]:
 (P/which).mkdir(exist_ok=True)
 for n,b in zip(names,blobs):(P/which/(n+'.bin')).write_bytes(b)
# Native G16-derived transaction pins all five before/after sectors.
c='// G80 exact G16-after preimage. Only userdata type and GPT CRCs change.\n'
c+='STATIC CONST EFI_LBA mGoldenGptLba[5]={0,1,2,0x7613bff,0x7613bfb};\n'
c+='STATIC CONST UINT8 mGoldenGpt[5][4096]={\n'+',\n'.join('{'+','.join('0x%02x'%v for v in b)+'}' for b in raw)+'};\n'
c+='#define OPEN_GPT_AFTER_ARRAY_CRC 0x%08xU\n'%crc
c+='#define OPEN_GPT_AFTER_PRIMARY_CRC 0x%08xU\n'%struct.unpack_from('<I',target[1],16)[0]
c+='#define OPEN_GPT_AFTER_BACKUP_CRC 0x%08xU\n'%struct.unpack_from('<I',target[3],16)[0]
(S/'OpenG80GoldenData.h').write_text(c)
changes=[{'region':n,'changed_bytes':sum(x!=y for x,y in zip(a,b)),'before_sha256':sha(a),'after_sha256':sha(b)} for n,a,b in zip(names,raw,target)]
assert sum(v['changed_bytes'] for v in changes)==48
(E/'gpt-plan-proof.json').write_text(json.dumps({'change':'userdata Android type to EFI System Partition; extents/names/unique GUIDs/attributes and other partitions unchanged','type_only_diagnostic':'userdata extent is deliberately unchanged; final partition layout remains later work','regions':changes,'changed_bytes':48,'phone_writes':0},indent=2))
