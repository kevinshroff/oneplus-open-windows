"""Read-only source/receipt audit and independent decode of the MODEL packet."""
from pathlib import Path
import argparse,hashlib,json,re,struct
p=argparse.ArgumentParser();p.add_argument('--output',type=Path);a=p.parse_args();W=Path(__file__).resolve().parent;ROOT=W.parents[1];E=ROOT/'evidence/G67';J=lambda n:json.loads((E/n).read_text());sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
for name in ['kernel-build.json','client-build.json']:
 m=J(name)
 for row in m['objects']:assert sha(W/row['source'])==row['source_sha256']
 for header,h in m['headers'].items():assert sha(W/header)==h
 assert sha(W/'inputs/g67_binding.h')==m['binding_sha256']
clock=J('clock-model.json');adapter=J('adapter-model.json');client=J('client-policy-model.json')
assert clock['passed']and clock['cases']==300 and adapter['passed']and adapter['cases']==47 and client['passed']and client['cases']==79
for m in [clock,client]:
 for name,h in m['source_sha256'].items():assert sha(W/name)==h
assert adapter['driver_source_sha256']==sha(W/'g67_driver.c')and not adapter['native_resource_handoff_or_clock_vote_qualified']
for name in ['kernel-source-reproduction.json','client-source-reproduction.json']:
 m=J(name);assert m['passed']and m['ARM64_objects_byte_identical']and m['native_operations']==0
 for source,h in m['source_sha256'].items():assert sha(W/source)==h
assert J('kernel-source-reproduction.json')['objects']==J('kernel-build.json')['objects']
assert J('client-source-reproduction.json')['objects']==J('client-build.json')['objects']
kernel=J('kernel-relink.json');assert kernel['phase']=='unsigned_kernel_PE_reproduced_byte_identically_from_hash_equal_clean_build_inputs'
assert kernel['unsigned_sha256']==J('signature-verification.json')['unsigned_driver_sha256']=='f7534b1c4dd66f0b1eed6b2afd21d513a0e3f134ed37ac2fea4448da0dfee7fa'
f=J('client-final-reproduction.json');assert f['passed']and f['two_fresh_host_links_byte_identical']and f['native_execution_receipts_apply_to_exact_final_bytes']
assert f['binary_sha256']=='1560529b8c0d46eabb54825a4cedaf07c743746f8df08b211a0e43c963116a87'and f['bytes']==14336 and f['explicit_valid_subsystem_profile']==[6,1,6,2]

source=J('source-map.json');assert source['fixed_trial_pages']==[0x118000,0x123000,0x152000]
assert [r['vote_bit']for r in source['clocks']]==[20,21,26]and all(r['vote_register']==0x152008 for r in source['clocks'])
assert [r['FDT_clock_id']for r in source['clocks']]==[127,128,101]
table=(E/'expected-trial-DSDT.bin').read_bytes();original=(E.parent/'G63/expected-trial-DSDT.bin').read_bytes()[:576];acpi=J('ACPI-build.json')
assert len(table)==742 and table[:4]==b'DSDT'and sum(table)%256==0 and struct.unpack_from('<I',table,4)[0]==len(table)
assert table[36:576]==original[36:]and hashlib.sha256(table).hexdigest()==acpi['trial_DSDT_sha256']=='1682de06510a8dc8f1d82a10be035e3ac9e8ecbd5b116f0ad160d8f43e1832f1'
header=(W/'inputs/g67_binding.h').read_text();assert bytes(int(x,16)for x in re.findall(r'0x([0-9a-f]{2})',header))==table
crs=(E/'expected-CRS.bin').read_bytes();wanted=b''.join(bytes.fromhex('86090001')+struct.pack('<II',p,4096)for p in source['fixed_trial_pages'])+bytes([0x79,0]);assert crs==wanted and len(crs)==38 and table.count(crs)==1
assert acpi['all_original_AML_body_bytes_preserved']and acpi['evaluated_marker_HID_STA_CCA_and_CRS_match']

raw=(E/'MODEL-NOT-NATIVE.bin').read_bytes();assert len(raw)==1872 and sha(E/'MODEL-NOT-NATIVE.bin')==adapter['model_packet_sha256']==client['fixture_sha256']
u=lambda at:struct.unpack_from('<I',raw,at)[0]
assert struct.unpack_from('<IIQ',raw)==(1872,1,0x314b4c433736504f)
assert [u(i)for i in range(16,88,4)]==[26100,8,0,742,1,0,1,0,1,0,1,0,3,3,1,7,3,0]
for base in [88,148]:
 for i,page in enumerate(source['fixed_trial_pages']):
  d=raw[base+i*20:base+(i+1)*20];assert d[:4]==bytes([3,1,0,0])and struct.unpack_from('<QI',d,4)==(page,4096)and d[16:]==bytes(4)
assert (u(208),u(212))==(1,0)and struct.unpack_from('<Q',raw,216)[0]==42
assert [u(i)for i in range(224,264,4)]==[0,0,1,0,33,6,0,39,0,0]
baseline=[0x40002380,0x80004000,0x80000000,0x100000,0,0x80000002]
assert list(struct.unpack_from('<6I',raw,264))==list(struct.unpack_from('<6I',raw,312))==baseline
rows=[struct.unpack_from('<4I',raw,336+i*16)for i in range(39)];assert sum(k==1 for k,_,_,_ in rows)==33
assert [v for k,reg,v,_ in rows if k==2 and reg==0]==[0x40102380,0x40302380,0x44302380,0x40302380,0x40102380,0x40002380]
assert raw[336+39*16:]==bytes(1872-336-39*16)

package=J('package-manifest.json');sig=J('signature-verification.json');cat=J('catalog-signature.json')
assert package['hardware_id']==r'ACPI\OPEN0067'and package['trial_DSDT_sha256']==acpi['trial_DSDT_sha256']
assert r'ACPI\OPEN0067'in(W/'OpenG67.inf').read_text()
correction=J('package-manifest-correction.json');assert correction['only_changed_key']=='hardware_id'and correction['all_signed_package_file_hashes_unchanged']and not correction['driver_installed']
assert correction['after_manifest_sha256']==sha(E/'package-manifest.json')
assert package['files']['OpenG67.sys']==sig['signed_driver_sha256']=='41131417c11e69b828c96b225da6c0bdf0028a26a75a8ecfd7cb8d9e6b475beb'
assert sig['SHA256_Authenticode_digest_matches_verified_CMS_content']and sig['all_loadable_sections_byte_identical_before_after_signing']and sig['REA_Ghidra_import_inventory_matches_PE_imports']
assert not sig['root_trust_store_changed']and not sig['private_key_exported']and not sig['production_trust_or_WHQL_claimed']
assert cat['CMS_signature_verified']and cat['sha256']==package['files']['OpenG67.cat']and not cat['root_store_changed']and not cat['private_key_exported']
assert J('REA-imports.json')['artifact_sha256']==sig['signed_driver_sha256']
assert J('REA-client-imports.json')['artifact_sha256']==f['binary_sha256']
assert len(J('REA-client-imports.json')['external_symbols'])==18 and J('client-verification.json')['REA_Ghidra_import_inventory_matches_PE']

n=J('native-client-refusals.json');assert n['binary_sha256']==f['binary_sha256']and n['staged_project_bytes']==14336
for mode in ['query','cycle']:
 assert n['native_refusals'][mode]=={'ok':False,'stage':'DSDT-length','error':576,'interfaces_queried':0,'file_opens':0,'ioctls':0}
assert n['native_refusals']['invalid-arguments']['stage']=='arguments'
assert n['before_and_after_original_audits_equal']and not n['driver_loaded']and not n['native_clock_vote_qualified']
comparisons=J('startup-comparisons.json');same=comparisons['same_path']
assert same['phase']=='same_path_native_header_dependency_confirmed_and_original_bytes_restored'and same['original_project_client_bytes_restored']and same['all_raw_sections_byte_identical']
assert same['compatible_execution']['exit_code']==1 and json.loads(same['compatible_execution']['output'])['stage']=='DSDT-length'
assert same['restored_original_execution']['exit_code']==0xc000007b and not same['precise_internal_loader_predicate_reconstructed']
assert comparisons['trace_key_removed']and sha(E/'native-loader-trace.txt')==comparisons['loader_trace_sha256']
final=J('final-state.json');assert final['clock-service-absent']and final['project-IFEO-absent']and final['health']['arch']=='arm64'and final['health']['cpus']==8
assert final['session']==n['session']and not final['new_driver_loaded']and not final['fresh_full_protected_partition_hash_audit_claimed']
assert final['original_software_audit']==json.loads((E.parent/'G64/native-recovered-files.json').read_text())['software_audit']
c=J('checkpoint.json');assert c['passed']and c['all21_goal_areas_active']and not c['native_clock_operation_qualified']and c['physical_tests_requested']==0
if(E/'manifest.json').exists():
 for entry in J('manifest.json')['files']:
  path=ROOT/entry['path'];assert path.stat().st_size==entry['bytes']and sha(path)==entry['sha256'],entry['path']
r={'passed':True,'source_build_signature_import_and_native_refusal_receipts_consistent':True,'MODEL_1872byte_packet_independently_decoded':True,'model_packet_is_native':False,'same_path_native_PE_version_dependency_observed':True,'exact_internal_loader_predicate_reconstructed':False,'native_clock_or_new_kernel_admission_qualified':False,'original_stack_trace_cleanup_and8CPU_control_preserved':True,'all21_goal_areas_active':True,'scope':'Local public evidence consistency and independent model decode; private binaries and native operations are not rerun.'}
if a.output:a.output.write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps(r))
