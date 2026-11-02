"""Independent G784/G778 offline RSA/CMS, PE payload and CAT member review.
No signing, trust, host/phone/native/queue operations. Run from workspace root.
"""
from pathlib import Path,PurePosixPath
import hashlib,json,zipfile,sys,stat,re
R=Path.cwd();W=Path(__file__).resolve().parent;O=W/'extracted'
sha=lambda b:hashlib.sha256(b).hexdigest()
def unique(pairs):
 d={}
 for k,v in pairs:assert k not in d,'duplicate JSON key';d[k]=v
 return d
def readj(b):return json.loads(b,object_pairs_hook=unique)
for name,digest in readj((W/'VERIFIER-HELPER-PINS.json').read_bytes()).items():assert sha((R/name).read_bytes())==digest,'unchanged crypto helper pin'
sys.path.insert(0,str(R/'work/gpu-gmu-signed-review'))
from crypto_primitives import cms,certificate_blob,indirect,pehash,catalog_entries,CERT_SHA,THUMB
sys.path.insert(0,str(R/'work/power-native-G194'))
from verify_signed_image import signed_image_digest
Z=R/'work/handover-resume-G737/G784-SignedGmuHfi.zip';H=R/'work/handover-resume-G737/G784-host-archive.json'
if not Z.exists() or not H.exists():raise SystemExit('PENDING actual G784 archive + host archive receipt; no review emitted')
host=readj(H.read_bytes());archive=Z.read_bytes()
assert type(host['zipBytes']) is int and host['zipBytes']>0 and len(archive)==host['zipBytes'] and re.fullmatch('[a-f0-9]{64}',host['zipSha']) and sha(archive)==host['zipSha']
prep=R/'work/gpu-g784-sign-prep';pinsraw=(prep/'input/PACKAGE-PINS.json').read_bytes()
assert sha(pinsraw)=='4960274395a5c171f0732d2a4291547d1adfb0c411bee2cea2508418621f81bc'
pins=readj(pinsraw);assert pins['schema']=='Open-GMU-HFI-two-actual-MSVC-sign-inputs/1' and pins['native_qualified'] is False and len(pins['inputs'])==10 and len(pins['images'])==2
assert pins['source_manifest_sha256']=='abf1aeb9845fc07ef3e59199b2c96c6a3aed713f4c2f778a4db9bb7ead1e71bd'==sha((R/'work/gpu-gbif-handoff-G778/MANIFEST.json').read_bytes())
assert pins['actual_MSVC_link_receipt_sha256']=='81e0bbe7d58c05f3d0b222d0c6f23fea596709b916ed774d92793cea924ddd60'
assert pins['root_unsigned_review_sha256']=='d9a330a21a0cf610ee65dd21129f2aa765212ec9d3635a7a17f3f6a1673d6faf'
# Canonical names and all archive bounds validated before writing extracted bytes.
index={};total=0
with zipfile.ZipFile(Z) as z:
 for item in z.infolist():
  name=item.filename.replace('\\','/').casefold();path=PurePosixPath(name)
  assert name and not path.is_absolute() and '..' not in path.parts and ':' not in name and not item.is_dir() and not stat.S_ISLNK(item.external_attr>>16)
  assert str(path)==name and name not in index and 0<item.file_size<4<<20
  total+=item.file_size;assert total<12<<20
  index[name]=z.read(item)
get=lambda name:index[name.casefold()]
assert get('PACKAGE-PINS.json')==pinsraw
reviewraw=(prep/'input/ROOT-UNSIGNED-REVIEW.json').read_bytes();assert get('ROOT-UNSIGNED-REVIEW.json')==reviewraw and sha(reviewraw)==pins['root_unsigned_review_sha256']
assert reviewraw==(R/'work/handover-resume-G737/G781-unsigned/ROOT-UNSIGNED-REVIEW.json').read_bytes()
rootreview=readj(reviewraw);assert rootreview['accepted_for_existing_certificate_signing'] is True and rootreview['not_native_hardware_qualification'] is True
receipt=readj(get('signed-receipt.json'));assert receipt['schema']=='Open-GMU-HFI-two-signed-packages/1' and receipt['phase']=='signed-two-packages-independent-crypto-review-pending' and receipt['cms_signatures_checked']==4
assert receipt['trust_changes']==receipt['installs']==receipt['host_pa_verifications']==0 and receipt['native_qualified'] is False
assert receipt['package_pins_sha256']==sha(pinsraw) and receipt['root_unsigned_review_sha256']==sha(reviewraw) and receipt['source_manifest_sha256']==pins['source_manifest_sha256']
assert receipt['signer']==THUMB and receipt['public_DER_sha256']==CERT_SHA
assert len(receipt['operations'])==6 and all(x['state']=='returned-success' and x['exit']==0 for x in receipt['operations'])
assert len(receipt['cms_checks'])==4 and all(x['state']=='CMS-signature-and-signer-verified' for x in receipt['cms_checks'])
assert readj(get('progress.json'))==receipt
# Exact workflow metadata; no extra package, catalog or archive member is admitted.
inputs={n.casefold():n for n in pins['inputs']};assert len(inputs)==10
catalogs={'packages/broker/opensmmud0-g778.cat','packages/owner-once/opengpustartonce-g778.cat'}
expected_package=set(inputs)|catalogs|{'g636-public.cer'}
logs={f'{operation}-{role}{suffix}.log' for role in ('broker','owner-once') for operation,suffix in [('sign','-driver'),('catalog',''),('sign','-catalog')]}
metadata={'root-unsigned-review.json','package-pins.json','progress.json','signed-receipt.json','signed-13-member-pins.json'}|logs
assert set(index)==expected_package|metadata,'unexpected/missing archive member'
reported_files={n.casefold():v for n,v in receipt['files'].items()};assert len(reported_files)==len(receipt['files']) and set(reported_files)==set(index)-{'progress.json','signed-receipt.json','signed-13-member-pins.json'}
for name,pin in reported_files.items():assert len(get(name))==pin['bytes'] and sha(get(name))==pin['sha256']
cert=get('g636-public.cer');assert sha(cert)==CERT_SHA and hashlib.sha1(cert).hexdigest().upper()==THUMB and cert==(prep/'source/G636-public.cer').read_bytes()
nonraw=(prep/'source/NON-SYS-PINS.json').read_bytes();assert sha(nonraw)=='24f628686d5bb310346b6fddcf709016382432f4ca4c40a4fb0c733eecb17e08'
non=readj(nonraw);assert len(non)==8
for name,pin in pins['inputs'].items():
 if not name.endswith('.sys'):
  b=get(name);assert len(b)==pin['bytes'] and sha(b)==pin['sha256'] and b==(prep/'input'/name).read_bytes() and non[name]==pin
for name,cat in [('packages/broker/OpenSmmuD0.inf','OpenSmmuD0-G778.cat'),('packages/owner-once/OpenGpuStartOnce.inf','OpenGpuStartOnce-G778.cat')]:
 text=get(name).decode();assert re.findall(r'(?m)^DriverVer=10/29/2026,1\.0\.0\.778\s*$',text) and re.findall(r'(?m)^CatalogFile='+re.escape(cat)+r'\s*$',text)
assert re.findall(r'(?m)^HKR,,BootstrapOnce,0x00010001,1\s*$',get('packages/owner-once/OpenGpuStartOnce.inf').decode())
images=[];cats=[];member_count=0
for role,sysname,catname in [('broker','OpenSmmuD0.sys','OpenSmmuD0-G778.cat'),('owner-once','OpenGpuStart.sys','OpenGpuStartOnce-G778.cat')]:
 prefix='packages/'+role+'/';signed=get(prefix+sysname);unsigned=(R/'work/handover-resume-G737/G781-unsigned'/sysname).read_bytes()
 assert sha(unsigned)==pins['images'][sysname]==pins['inputs'][prefix+sysname]['sha256'] and len(unsigned)==pins['inputs'][prefix+sysname]['bytes']
 assert unsigned==(prep/'input'/prefix/sysname).read_bytes()
 row=next(x for x in rootreview['images'] if x['name']==sysname);assert row['sha256']==sha(unsigned) and row['bytes']==len(unsigned) and row['unsigned_certificate_empty'] is True and row['no_writable_executable_sections'] is True
 digest=signed_image_digest(signed,unsigned)
 content,proof=cms(certificate_blob(signed),cert,'1.3.6.1.4.1.311.2.1.4');algorithm,embedded=indirect(content)
 assert algorithm=='sha256' and embedded.hex()==digest and embedded==pehash(signed,'sha256')
 images.append(dict(path=prefix+sysname,signed_sha256=sha(signed),unsigned_sha256=sha(unsigned),authenticode_sha256=digest,unsigned_image_unchanged_except_signing_metadata=True,**proof))
 cat=get(prefix+catname);ctl,proof=cms(cat,cert,'1.3.6.1.4.1.311.10.1');entries=catalog_entries(ctl)
 expected={n[len(prefix):].casefold():n for n in pins['inputs'] if n.startswith(prefix)};seen=set();explicit=set();keys=set();verified=[]
 for name,algorithm,digest,binding in entries:
  assert name in expected,'extra catalog member';key=(name,algorithm,binding);assert key not in keys,'duplicate catalog binding';keys.add(key)
  full=expected[name];b=get(full);actual=pehash(b,algorithm) if name.endswith('.sys') else hashlib.new(algorithm,b).digest();assert actual==digest,'catalog member digest mismatch'
  seen.add(name)
  if binding=='explicit_SpcIndirectData_digest' and algorithm=='sha256':explicit.add(name)
  verified.append(dict(path=full,algorithm=algorithm,digest=digest.hex(),binding=binding))
 assert seen==explicit==set(expected),'missing explicit SHA256 catalog member'
 member_count+=len(seen);cats.append(dict(path=prefix+catname,sha256=sha(cat),unique_members=len(seen),no_extra_members=True,entries=verified,**proof))
assert member_count==10
package={n:dict(bytes=len(b),sha256=sha(b)) for n,b in index.items() if n.startswith('packages/') or n=='g636-public.cer'}
assert len(package)==13 and set(package)==expected_package
hostpins=readj(host['memberPins']) if isinstance(host['memberPins'],str) else host['memberPins']
assert hostpins['files']==package and readj(get('SIGNED-13-MEMBER-PINS.json'))['files']==package
result=dict(status='PASSED_INDEPENDENT_PORTABLE_CRYPTO_CONTENT_REVIEW',archive_sha256=sha(archive),archive_bytes=len(archive),host_archive_receipt_sha256=sha(H.read_bytes()),package_input_pins_sha256=sha(pinsraw),root_unsigned_review_sha256=sha(reviewraw),source_manifest_sha256=pins['source_manifest_sha256'],RSA_SHA256_CMS_signatures_verified=4,embedded_Authenticode_digests_verified=2,unsigned_image_payloads_preserved=2,non_SYS_inputs_exact=8,catalog_unique_input_members_verified=10,catalog_no_extra_members=True,signed_package_members_including_two_catalogs=12,package_members_with_public_DER=13,package_version='1.0.0.778',exact_existing_DER_sha256=CERT_SHA,thumbprint_SHA1=THUMB,images=images,catalogs=cats,canonical_extracted_paths_lowercase=True,native_load_or_hardware_qualified=False,trust_chain_policy_or_phone_trust_claimed=False,signing_trust_install_target_operations=0,limits=['Portable RSA/CMS/content math does not establish Windows kernel trust, catalog installation, native loading or hardware behavior.','No timestamp, chain or revocation policy qualification is asserted.'])
# Emit review/pins only after all actual checks pass. Preserve any prior bytes.
O.mkdir(exist_ok=True)
for name,data in index.items():
 dest=O/name;dest.parent.mkdir(parents=True,exist_ok=True)
 if dest.exists():assert dest.read_bytes()==data,'preserve prior extraction'
 else:dest.write_bytes(data)
for name,value in [('REVIEW.json',result),('SIGNED-13-MEMBER-PINS.json',dict(files=package))]:
 dest=W/name;data=(json.dumps(value,indent=2)+'\n').encode()
 if dest.exists():assert dest.read_bytes()==data,'preserve prior result'
 else:dest.write_bytes(data)
print(json.dumps({k:v for k,v in result.items() if k not in ('images','catalogs')},indent=2))
