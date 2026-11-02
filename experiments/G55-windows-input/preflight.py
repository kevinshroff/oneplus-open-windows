"""Pin the software replay, native adapter and helper evidence before installation."""
from pathlib import Path
import hashlib,json
W=Path(__file__).resolve().parent;j=lambda p:json.loads(p.read_text());sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
compile=j(W/'private/compile-01/compile.json');assert len(compile['objects'])==5
for x in compile['objects']:assert sha(W/x['source'])==x['source_sha256']and sha(W/'private/compile-01'/x['object'])==x['sha256']
for n,h in compile['headers'].items():assert sha(W/n)==h
for path,count in [('private/report-01/tests.json',66435),('private/replay-02/tests.json',27),('private/driver-model-01/tests.json',37),('private/ABI-04/tests.json',7)]:
 v=j(W/path);assert v['passed']and(len(v['cases'])if isinstance(v['cases'],list)else v['cases'])==count
 if isinstance(v.get('source_sha256'),dict):
  for n,h in v['source_sha256'].items():assert sha(W/n)==h
driver=j(W/'private/driver-model-01/tests.json');assert driver['driver_sha256']==sha(W/'g55_driver.c')and driver['protocol_sha256']==sha(W/'g55_protocol.h')
abi=j(W/'private/ABI-04/tests.json');assert abi['source_sha256']==sha(W/'g55_admin.go')and abi['protocol_sha256']==sha(W/'g55_protocol.h')
for name,folder in [('admin','admin-04'),('receiver','receiver-05')]:
 b=j(W/'private'/folder/'build.json');assert b['source_sha256']==sha(W/('g55_'+name+'.go'))and b['binary_sha256']==sha(W/'private'/folder/('g55-'+name+'-arm64.exe'))
layout=j(W/'private/hid-layout-02/tests.json');assert layout['passed']and layout['ARM64_compile_assertions']==14 and layout['HIDP_VALUE_CAPS_bytes']==72
for v in j(W/'core-provenance.json')['cores']:assert sha(W/v['new'])==v['new_sha256']and sha(Path(v['qualified_source']))==v['qualified_source_sha256']
signature=j(W/'signature-verification.json');assert sha(W/'private/G55-signed.sys')==signature['signed_driver_sha256']and signature['SHA256_Authenticode_digest_matches_verified_CMS_content']and signature['all_loadable_sections_byte_identical_before_after_signing']
assert not signature['root_trust_store_changed']and not signature['production_trust_or_WHQL_claimed']
for values in signature['imports'].values():assert not any(v.startswith(('MmMapIoSpace','ZwWriteFile','NtWriteFile'))for v in values)
assert r'OPENLAB\ONEPLUSOPENTOUCHG55' in(W/'G55Vhf.inf').read_text()and'HID_DEVICE_SYSTEM_VHF'not in(W/'G55Vhf.inf').read_text()
v={'passed':True,'five_native_objects_and_all_current_sources_pinned':True,'driver_model_cases':37,'replay_cases':27,'descriptor_cases':66435,'ABI_cases':7,'HID_layout_assertions':14,'signed_driver_sha256':signature['signed_driver_sha256'],'no_native_MMIO_or_raw_storage_API':True,'native_input_or_binding_qualified_by_this_check':False}
(W/'preflight.json').write_text(json.dumps(v,indent=2)+'\n');print(json.dumps(v))
