from pathlib import Path
import hashlib,json,struct,zipfile
w=Path(__file__).resolve().parent/'private';sha=lambda b:hashlib.sha256(b).hexdigest()
built=json.loads(json.loads((w/'build-result.json').read_text())['output']);assert sha((w/'G137-package.zip').read_bytes())==built['zip_sha256']
def members(path):
 with zipfile.ZipFile(path)as z:
  files={}
  for n in z.namelist():
   name=n.replace('\\','/').lower()
   if name.endswith('/'):continue
   assert not name.startswith('/') and all(p not in ['.','..','']for p in name.split('/'))and name not in files
   files[name]=z.read(n)
  return files
byname=members(w/'G137-package.zip');expected={'root/openg98.sys','root/openg98.inf','root/openg98.cat','root/g98-public.cer','root/package.json','g98-admin.exe','g137-keys.exe'};assert set(byname)==expected
manifest=json.loads(byname['root/package.json']);assert sha(byname['root/package.json'])==built['manifest_sha256'];assert manifest['version']=='G98-package-1'
for n,h in manifest['files'].items():assert sha(byname['root/'+n.lower()])==h
assert set(n.lower()for n in manifest['files'])=={'openg98.sys','openg98.inf','openg98.cat','g98-public.cer'}
driver=byname['root/openg98.sys'];assert sha(driver)==built['driver_sha256'];pe=struct.unpack_from('<I',driver,60)[0];assert driver[pe:pe+4]==b'PE\0\0'and struct.unpack_from('<H',driver,pe+4)[0]==0xaa64
assert b'0.0.98.5'in byname['root/openg98.inf'];assert byname['g137-keys.exe']==(w/'G137-keys.exe').read_bytes();(w/'OpenG98-G137-signed.sys').write_bytes(driver)
old=members(w.parent.parent/'power-keys-G100/touch/private/G100-package.zip');assert byname['g98-admin.exe']==old['g98-admin.exe'];assert byname['root/g98-public.cer']==old['root/g98-public.cer']
report={'passed':True,'driver_SHA256':sha(driver),'package_SHA256':built['zip_sha256'],'manifest_SHA256':built['manifest_sha256'],'candidate_INF_version':'0.0.98.5','candidate_machine':'ARM64','new_client_SHA256':sha(byname['g137-keys.exe']),'original_admin_byte_identical':True,'existing_public_certificate_byte_identical':True,'CMS_signatures_checked_on_laptop':built['cms_signatures_verified'],'private_key_exported':False,'trust_store_changed':False,'phone_installations':0,'phone_commands':0,'limits':'Linked and signed candidate only; no native G137 key capture/retirement, physical key mapping or Windows button events.'}
(w/'package-audit.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
