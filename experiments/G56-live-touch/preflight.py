"""Pin the actual production graph, live tests, ABI and owned helpers."""
from pathlib import Path
import argparse,hashlib,json
W=Path(__file__).resolve().parent;p=argparse.ArgumentParser();p.add_argument('--unsigned',action='store_true');a=p.parse_args();j=lambda p:json.loads(p.read_text());sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
c=j(W/'private/compile-01/compile.json');assert len(c['objects'])==16
for x in c['objects']:assert sha(W/x['source'])==x['source_sha256']and sha(W/'private/compile-01'/x['object'])==x['sha256']
for n,h in c['headers'].items():assert sha(W/n)==h
assert sha(W/'private/inputs/g56_binding.h')==c['binding_sha256']
checks=[('private/trial-model-04/tests.json',15755),('private/live-model-03/tests.json',720),('private/driver-model-02/tests.json',77),('private/adapter-policy-01/tests.json',23104),('private/ABI-02/tests.json',25)]
for path,count in checks:
 d=j(W/path);assert d['passed']and d['cases']==count
 if isinstance(d.get('source_sha256'),dict):
  for n,h in d['source_sha256'].items():assert sha(W/n)==h
 if 'adapter_sha256'in d:assert sha(W/'g56_hardware.c')==d['adapter_sha256']
 if path.endswith('ABI-02/tests.json'):assert sha(W/'g56_hwdecode.go')==d['source_sha256']
hid=j(W/'private/HID-ABI-01/tests.json');assert hid['passed']and len(hid['cases'])==7 and hid['source_sha256']==sha(W/'g56_admin.go')and hid['protocol_sha256']==sha(W/'g56hid_protocol.h')
for r in j(W/'core-provenance.json')['cores']:assert sha(W/r['new'])==r['new_sha256']and sha(Path(r['qualified_source']))==r['qualified_source_sha256']and r['namespace_include_normalized_equal']
for name,folder in [('admin','admin-03'),('receiver','receiver-01'),('child','child-01'),('cleanup','cleanup-01')]:
 d=j(W/'private'/folder/'build.json');assert sha(W/'private'/folder/('g56-'+name+'-arm64.exe'))==d['binary_sha256']
 for n,h in d.get('source_files_sha256',{d['source']:d['source_sha256']}).items():assert sha(W/n)==h
assert 'test-fixtures.h'not in(W/'g56_driver.c').read_text()and 'g56_replay'not in json.dumps(c)
assert r'OPENLAB\ONEPLUSOPENTOUCHG56'in(W/'G56Vhf.inf').read_text()and'HID_DEVICE_SYSTEM_VHF'not in(W/'G56Vhf.inf').read_text()
v={'passed':True,'all16_production_objects_and_headers_pinned':True,'hardware_model_cases':15755,'live_pump_cases':720,'root_dispatch_cases':77,'actual_adapter_policy_cases':23104,'C_Go_ABI_cases':25,'HID_status_ABI_cases':7,'production_contains_no_fixture_or_replay_module':True,'native_live_input_qualified_by_this_check':False}
if not a.unsigned:
 d=j(W/'signature-verification.json');assert sha(W/'private/G56-signed.sys')==d['signed_driver_sha256']and d['SHA256_Authenticode_digest_matches_verified_CMS_content']and d['all_loadable_sections_byte_identical_before_after_signing']and not d['root_trust_store_changed']and not d['production_trust_or_WHQL_claimed'];v['signed_driver_sha256']=d['signed_driver_sha256']
(W/('preflight-unsigned.json'if a.unsigned else'preflight.json')).write_text(json.dumps(v,indent=2)+'\n');print(json.dumps(v))
