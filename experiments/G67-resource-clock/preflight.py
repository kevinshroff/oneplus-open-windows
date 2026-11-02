"""Audit the clock package's source/build contracts without native installation."""
from pathlib import Path
import hashlib,json
W=Path(__file__).resolve().parent;P=W/'private';J=lambda p:json.loads(p.read_text());sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
clock=J(P/'clock-model-03/tests.json');driver=J(P/'driver-model-04/tests.json');client=J(P/'client-policy-01/tests.json')
assert clock['passed']and clock['cases']==300 and driver['passed']and driver['cases']==47 and client['passed']and client['cases']==79
for proof in [clock,client]:
 for name,h in proof['source_sha256'].items():assert sha(W/name)==h,name
assert driver['driver_source_sha256']==sha(W/'g67_driver.c')and driver['binding_sha256']==sha(P/'acpi-02/g67_binding.h')
assert driver['model_packet_sha256']==client['fixture_sha256']==sha(P/'driver-model-04/MODEL-NOT-NATIVE.bin')
c=J(P/'compile-03/compile.json')
for row in c['objects']:assert sha(W/row['source'])==row['source_sha256']and sha(P/'compile-03'/row['object'])==row['sha256']
for name,h in c['headers'].items():assert sha(W/name)==h
assert c['binding_sha256']==driver['binding_sha256']
table=(P/'acpi-02/acpitabl.dat').read_bytes();a=J(P/'acpi-02/build.json');assert len(table)==742 and sha(P/'acpi-02/acpitabl.dat')==a['trial_DSDT_sha256']=='1682de06510a8dc8f1d82a10be035e3ac9e8ecbd5b116f0ad160d8f43e1832f1'
assert table[36:576]==(W.parent/'resources-G63/private/acpi-02/acpitabl.dat').read_bytes()[36:576]and sum(table)%256==0
sig=J(W/'signature-verification.json');assert sig['signed_driver_sha256']==sha(P/'G67-signed.sys')and sig['SHA256_Authenticode_digest_matches_verified_CMS_content']and sig['all_loadable_sections_byte_identical_before_after_signing']and sig['REA_Ghidra_import_inventory_matches_PE_imports']
assert not sig['root_trust_store_changed']and not sig['private_key_exported']
if(P/'package.json').exists():
 package=J(P/'package.json');assert package['hardware_id']==r'ACPI\OPEN0067'and package['files']['OpenG67.sys']==sha(P/'G67-signed.sys')
r={'passed':True,'clock_cases':300,'actual_adapter_cases':47,'client_policy_cases':79,'trial_DSDT_bytes':742,'signed_driver_sha256':sig['signed_driver_sha256'],'native_resource_handoff_or_clock_vote_qualified':False,'driver_loaded':False,'production_trust_qualified':False,'all21_goal_areas_active':True,'scope':'Source/build/model and compiled signature/import consistency; not native installation or hardware evidence.'};(W/'preflight.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r))
