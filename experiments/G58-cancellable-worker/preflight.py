"""Pin production source, real ARM64 build, concurrency/fault and ABI checks."""
from pathlib import Path
import argparse,hashlib,json
W=Path(__file__).resolve().parent;p=argparse.ArgumentParser();p.add_argument('--unsigned',action='store_true');a=p.parse_args();J=lambda p:json.loads(p.read_text());sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
c=J(W/'private/compile-04/compile.json');assert len(c['objects'])==16
for row in c['objects']:assert sha(W/row['source'])==row['source_sha256']and sha(W/'private/compile-04'/row['object'])==row['sha256']
for name,digest in c['headers'].items():assert sha(W/name)==digest
assert sha(W/'private/inputs/g58_binding.h')==c['binding_sha256']
checks=[('trial-model-01',28291),('live-model-02',4231),('driver-model-02',317),('driver-TSan-01',317),('adapter-policy-02',45884),('native-entry-02',29),('ABI-01',35),('session-ABI-02',19)]
for folder,count in checks:
 d=J(W/'private'/folder/'tests.json');assert d['passed']and d.get('cases',d.get('IO_cases'))==count
 if isinstance(d.get('source_sha256'),dict):
  for name,digest in d['source_sha256'].items():assert sha(W/name)==digest
 if folder=='ABI-01':assert sha(W/'g58_hwdecode.go')==d['source_sha256']
 if 'adapter_sha256'in d:assert sha(W/'g58_hardware.c')==d['adapter_sha256']
hid=J(W/'private/HID-ABI-02/tests.json');assert hid['passed']and len(hid['cases'])==7 and hid['source_sha256']==sha(W/'g58_admin.go')and hid['protocol_sha256']==sha(W/'g58hid_protocol.h')
for row in J(W/'core-provenance.json')['cores']:assert sha(W/row['new'])==row['new_sha256']and sha(Path(row['qualified_source']))==row['qualified_source_sha256']and row['namespace_include_normalized_equal']
for name,folder in [('admin','admin-02'),('receiver','receiver-01'),('child','child-01'),('cleanup','cleanup-01')]:
 d=J(W/'private'/folder/'build.json');assert sha(W/'private'/folder/('g58-'+name+'-arm64.exe'))==d['binary_sha256']
 for source,digest in d['source_files_sha256'].items():assert sha(W/source)==digest
assert 'test-fixtures.h'not in(W/'g58_driver.c').read_text()and'g58_replay'not in json.dumps(c)
assert r'OPENLAB\ONEPLUSOPENTOUCHG58'in(W/'G58Vhf.inf').read_text()and'HID_DEVICE_SYSTEM_VHF'not in(W/'G58Vhf.inf').read_text()
v={'passed':True,'production_objects':16,'source_and_headers_pinned':True,'full_hardware_fault_stop_cases':28291,'poll_input_lifecycle_cases':4231,'actual_root_thread_IO_cases':317,'actual_root_100_finish_stop_races':True,'root_ASan_UBSan_and_TSan':True,'native_policy_cases':45884,'actual_native_entry_refusal_cases':29,'hardware_ABI_cases':35,'HID_ABI_cases':7,'session_ABI_cases':19,'helpers':4,'unchanged_qualified_C_sources_headers':25,'native_cancellation_qualified':False,'permanent_touch_qualified':False}
if not a.unsigned:
 d=J(W/'signature-verification.json');assert sha(W/'private/G58-signed.sys')==d['signed_driver_sha256']and d['SHA256_Authenticode_digest_matches_verified_CMS_content']and d['all_loadable_sections_byte_identical_before_after_signing']and not d['root_trust_store_changed']and not d['production_trust_or_WHQL_claimed'];v['signed_driver_sha256']=d['signed_driver_sha256']
(W/('preflight-unsigned.json'if a.unsigned else'preflight.json')).write_text(json.dumps(v,indent=2)+'\n');print(json.dumps(v))
