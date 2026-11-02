from pathlib import Path
import json,hashlib,zipfile
w=Path(__file__).resolve().parent;b=w.parents[1]/'work/gpu-cold-start-reconcile-G736/src'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
rows=json.loads((w/'build/COMPILE.json').read_text());assert len(rows)==42
coff={}
for target in ['owner','broker']:
 objs=[x for x in rows if x['target']==target];changed=[]
 for row in objs:
  f=w/row['object'];data=f.read_bytes();assert data[:2]==b'\x64\xaa' and data[4:8]==bytes(4)
  if data!=(b/row['object']).read_bytes():changed.append(row['source'])
 coff[target]={'total':len(objs),'changed':changed,'exact_unchanged':len(objs)-len(changed)}
assert len(coff['owner']['changed'])==4 and len(coff['broker']['changed'])==3
# Confirm complete response inventories and exact reused libraries.
for target in ['owner','broker']:
 lines=(w/'build'/(target+'.rsp')).read_text().splitlines();objects=[x for x in lines if x.endswith('.obj')];assert objects==[x['object'] for x in rows if x['target']==target]
 for x in lines:
  if x.endswith('.lib'):assert (w/x).read_bytes()==(b/x).read_bytes()
for n in ['OpenSmmuD0.inf','OpenGpuStartOnce.inf']:
 path=w/'packages'/('broker' if n.startswith('OpenSmmu') else 'owner-once')/n
 assert 'DriverVer=10/29/2026,1.0.0.778' in path.read_text() and '-G778.cat' in path.read_text()
review=json.loads((w/'REVIEW.json').read_text());review['COFF_package_changes']=coff;(w/'REVIEW.json').write_text(json.dumps(review,indent=2)+'\n')
# Frozen native input capsule. Host test executables and mutable output logs are
# excluded; there are no unsigned .sys placeholders in this packet.
files=[]
for folder in ['source','reference','packages','msvc-inputs/libraries','tests','evidence']:
 files.extend(f for f in (w/folder).rglob('*') if f.is_file() and '__pycache__' not in str(f))
files.extend(w/x['object'] for x in rows)
files.extend(w/'build'/(t+'.rsp') for t in ['owner','broker'])
files.extend(w/n for n in ['Relink-Reviewed.ps1','REPORT.md','REVIEW.json','G778-DELTA.patch','validate.py','package.py'])
files.append(w/'build/COMPILE.json');files=sorted(set(files));assert not any(f.suffix.lower()=='.sys' for f in files)
manifest={'schema':'G778-cold-reset-native-source-link-inputs/1','files':{str(f.relative_to(w)):{'bytes':f.stat().st_size,'sha256':sha(f)} for f in files},'native_load_qualified':False}
(w/'MANIFEST.json').write_text(json.dumps(manifest,indent=2)+'\n');h=sha(w/'MANIFEST.json')
command="& .\\Relink-Reviewed.ps1 -InputRoot '<EXTRACTED_G778_ROOT>' -ExpectedManifestSha256 '"+h+"' -Linker '<EXACT_MSVC14.29_LINK.EXE>' -ExpectedLinkerSha256 '7d80b89e242e2ab4d002c3b3508361a45691a01bd1f4be4d19eb765c8d319762' -OutputDirectory '<FRESH_EXTERNAL_G778_NATIVE_OUTPUT>' -ExecuteLink\n"
(w/'ROOT-NATIVE-LINK-COMMAND.txt').write_text(command)
archive=w/'G778-ColdReset-Source-LinkInputs.zip'
with zipfile.ZipFile(archive,'w',compression=zipfile.ZIP_DEFLATED) as z:
 for f in files+[w/'MANIFEST.json',w/'ROOT-NATIVE-LINK-COMMAND.txt']:z.write(f,str(f.relative_to(w)))
with zipfile.ZipFile(archive) as z:
 for n,p in manifest['files'].items():a=z.read(n);assert len(a)==p['bytes'] and hashlib.sha256(a).hexdigest()==p['sha256']
result={'source_manifest_sha256':h,'zip_sha256':sha(archive),'zip_bytes':archive.stat().st_size,'native_link_script_sha256':sha(w/'Relink-Reviewed.ps1'),'script_exact_G736':(w/'Relink-Reviewed.ps1').read_bytes()==(b/'Relink-Reviewed.ps1').read_bytes(),'COFF_package_changes':coff,'packages':{'broker':{'version':'1.0.0.778','catalog':'OpenSmmuD0-G778.cat'},'owner-once':{'version':'1.0.0.778','catalog':'OpenGpuStartOnce-G778.cat'}},'future_actual_unsigned_images_provided':False,'native_signing_acceptance':False,'native_calls':0}
(w/'READY-PINS.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
