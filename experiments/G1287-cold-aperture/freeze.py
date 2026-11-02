"""Freeze offline source/COFF/native owner-link inputs; no native link/sign/runtime."""
from pathlib import Path
import json,hashlib,zipfile,difflib
W=Path(__file__).resolve().parent;B=W.parent/'gpu-bv-shadow-G1148';sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();rows=json.loads((W/'build/COMPILE.json').read_text());assert len(rows)==50 and sum(r['target']=='owner' for r in rows)==35
for r in rows:assert sha(W/r['source'])==r['source_sha256'] and sha(W/r['object'])==r['sha256'] and not r['stderr'] and not r['exit_code']
for r in rows:
 if r['target']=='broker':assert (W/r['object']).read_bytes()==(B/r['object']).read_bytes()
assert (W/'reference/runtime/g456_hwinit.c').read_bytes()==(W.parent/'gpu-cp-ahb-response-policy-candidate/reference/runtime/g456_hwinit.c').read_bytes()
changes=[];patch=[]
for folder in ['source','reference']:
 for p in sorted((W/folder).rglob('*')):
  if not p.is_file():continue
  rel=p.relative_to(W);old=B/rel
  if not old.exists() or p.read_bytes()!=old.read_bytes():
   if str(rel)=='reference/runtime/g456_hwinit.c':continue # actual G1224 overlay baseline
   changes.append(str(rel));patch.extend(difflib.unified_diff(old.read_text().splitlines(True) if old.exists() else [],p.read_text().splitlines(True),fromfile='G1224/'+str(rel),tofile='G1287/'+str(rel)))
(W/'DELTA.patch').write_text(''.join(patch));(W/'evidence/SOURCE-CLOSURE.json').write_text(json.dumps({'actual_baseline':'G1148 source plus G1224 exact g456 overlay','changed_source_files':changes,'changed_existing_C_TUs':['source/owner/owner_entry.c','source/owner/bootstrap.c','source/native_bootstrap.c'],'new_assembly_TU':'source/owner/scm_set_cp0.S','unchanged_broker_objects':15,'owner_link_objects':35,'original_49_recompiled':True,'native_link_performed':False,'monitor_calls':0},indent=2)+'\n')
files=[]
for folder in ['source','reference','packages','msvc-inputs/libraries','native-inputs','evidence']:
 files.extend(p for p in (W/folder).rglob('*') if p.is_file() and p.suffix.lower() not in ['.sys','.cat'])
files += [W/r['object'] for r in rows]
files += [W/x for x in ['build/COMPILE.json','build/BASE-COMPILE.json','build/CHANGED-OBJECTS.json','build/owner.rsp','build/broker.rsp','README.md','DELTA.patch','compile_all.py','freeze.py','Relink-Owner-Reviewed.ps1','test_native_path.py','tests/test_native_cp_path.c','tests/test_aperture.py','tests/test_owner_aperture.py','tests/APERTURE-RESULT.json','tests/OWNER-APERTURE-RESULT.json','tests/aperture-layout.c','tests/baseline-layout.c']]
files += list((W/'build/host-cp').glob('*.h'))
# Frozen actor input set sufficient for the inherited CP actor, without CPU binaries.
files += [p for p in (W/'tests').glob('*') if p.suffix in ['.c','.h']]
files=sorted(set(files));m={'schema':'g1287-cold-aperture-owner-native-inputs/1','object_count':50,'owner_objects':35,'broker_objects':15,'native_link_targets':['owner'],'private_ABI':6,'owner_version':'1.0.0.1287','broker_reuse_version':'1.0.0.1148','ScmApertureOnce_default':0,'native_link_performed':False,'signing_performed':False,'hardware_qualified':False,'files':{str(p.relative_to(W)):{'bytes':p.stat().st_size,'sha256':sha(p)} for p in files}}
(W/'MANIFEST.json').write_text(json.dumps(m,indent=2)+'\n');mh=sha(W/'MANIFEST.json');(W/'ROOT-NATIVE-LINK-COMMAND.txt').write_text("& .\\Relink-Owner-Reviewed.ps1 -InputRoot '<EXTRACTED_G1287_ROOT>' -ExpectedManifestSha256 '"+mh+"' -Linker '<PINNED_MSVC14.29_LINK.EXE>' -ExpectedLinkerSha256 '7d80b89e242e2ab4d002c3b3508361a45691a01bd1f4be4d19eb765c8d319762' -OutputDirectory '<FRESH_EXTERNAL_G1287_OUTPUT>' -ExecuteLink\n")
z=W/'G1287-Source-NativeOwnerInputs.zip'
with zipfile.ZipFile(z,'w',zipfile.ZIP_DEFLATED) as a:
 for p in files+[W/'MANIFEST.json',W/'ROOT-NATIVE-LINK-COMMAND.txt']:a.write(p,str(p.relative_to(W)))
with zipfile.ZipFile(z) as a:
 assert len(a.namelist())==len(set(a.namelist()))
 for n,v in m['files'].items():assert hashlib.sha256(a.read(n)).hexdigest()==v['sha256']
pins={'schema':'g1287-offline-ready/1','manifest_sha256':mh,'zip_sha256':sha(z),'zip_bytes':z.stat().st_size,'compile_json_sha256':sha(W/'build/COMPILE.json'),'source_closure_sha256':sha(W/'evidence/SOURCE-CLOSURE.json'),'selected_resource_return_report_sha256':sha(W/'evidence/G1285-RESOURCE-RETURN-REVIEW.md'),'owner_objects':35,'broker_objects_unchanged':15,'native_link_targets':['owner'],'native_link_performed':False,'accepted_for_signing':False,'monitor_calls':0,'hardware_qualified':False};(W/'READY-PINS.json').write_text(json.dumps(pins,indent=2)+'\n');print(json.dumps(pins,indent=2))
