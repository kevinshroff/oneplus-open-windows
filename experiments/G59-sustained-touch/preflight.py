"""Pin native objects, policy/lifetime/fault tests and ring-aware collectors."""
from pathlib import Path
import argparse,hashlib,json
W=Path(__file__).resolve().parent;p=argparse.ArgumentParser();p.add_argument('--unsigned',action='store_true');a=p.parse_args();J=lambda p:json.loads(p.read_text());sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
c=J(W/'private/compile-02/compile.json');assert len(c['objects'])==16
for row in c['objects']:assert sha(W/row['source'])==row['source_sha256']and sha(W/'private/compile-02'/row['object'])==row['sha256']
for name,h in c['headers'].items():assert sha(W/name)==h
assert sha(W/'private/inputs/g59_binding.h')==c['binding_sha256']
checks=[('trial-model-01',29071),('live-model-02',4244),('owner-model-01',317),('owner-tsan-01',317),('startup-policy-01',218),('cycle-policy-01',440521),('native-entry-01',29),('hardware-abi-02',63),('session-abi-01',19)]
for folder,count in checks:
 d=J(W/'private'/folder/'tests.json');assert d['passed']and d.get('cases',d.get('IO_cases'))==count,(folder,d)
 if isinstance(d.get('source_sha256'),dict):
  for name,h in d['source_sha256'].items():assert sha(W/name)==h,(folder,name)
 if folder.startswith('hardware-abi'):assert sha(W/'g59_hwdecode.go')==d['source_sha256']and d['ring_cases']==24
 if 'adapter_sha256'in d:assert sha(W/'g59_hardware.c')==d['adapter_sha256']
hid=J(W/'private/hid-abi-01/tests.json');assert hid['passed']and len(hid['cases'])==7 and hid['source_sha256']==sha(W/'g59_admin.go')and hid['protocol_sha256']==sha(W/'g59hid_protocol.h')
for row in J(W/'core-provenance.json')['sources']:assert sha(W/row['source'])==row['new_sha256']and sha(Path(row['qualified_source']))==row['qualified_source_sha256']
for name in ['admin','receiver','child','cleanup']:
 folder=W/'private'/(name+'-01');d=J(folder/'build.json');assert sha(folder/('g59-'+name+'-arm64.exe'))==d['binary_sha256']
 for source,h in d['source_files_sha256'].items():assert sha(W/source)==h
assert 'test-fixtures.h'not in(W/'g59_driver.c').read_text()and'test-'not in json.dumps(c)
assert r'OPENLAB\ONEPLUSOPENTOUCHG59'in(W/'G59Vhf.inf').read_text()and'HID_DEVICE_SYSTEM_VHF'not in(W/'G59Vhf.inf').read_text()
v={'passed':True,'production_objects':16,'source_headers_policy_tests_and_helpers_pinned':True,'full_hardware_fault_stop_cases':29071,'poll_input_lifecycle_cases':4244,'actual_root_thread_IO_cases':317,'root_ASan_UBSan_and_TSan':True,'startup_policy_cases':218,'native_cycle_policy_cases':440521,'actual_native_entry_refusal_cases':29,'hardware_ABI_cases':63,'ring_ABI_cases':24,'HID_ABI_cases':7,'session_ABI_cases':19,'helpers':4,'native_cycles':2500,'maximum_cycles':3000,'native_sustained_touch_qualified':False,'permanent_touch_qualified':False}
if not a.unsigned:
 d=J(W/'signature-verification.json');assert sha(W/'private/G59-signed.sys')==d['signed_driver_sha256']and d['SHA256_Authenticode_digest_matches_verified_CMS_content']and d['all_loadable_sections_byte_identical_before_after_signing']and not d['root_trust_store_changed']and not d['production_trust_or_WHQL_claimed'];v['signed_driver_sha256']=d['signed_driver_sha256']
(W/('preflight-unsigned.json'if a.unsigned else'preflight.json')).write_text(json.dumps(v,indent=2)+'\n');print(json.dumps(v))
