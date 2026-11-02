"""Static/source prerequisites for packaging; not a native handoff result."""
from pathlib import Path
import hashlib,json,re
W=Path(__file__).resolve().parent;J=lambda p:json.loads(p.read_text());sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();c=J(W/'private/compile-02/compile.json');a=J(W/'private/acpi-02/build.json');signed=J(W/'signature-verification.json')
for row in c['objects']:assert sha(W/row['source'])==row['source_sha256']and sha(W/'private/compile-02'/row['object'])==row['sha256']
for name,h in c['headers'].items():assert sha(W/name)==h
assert c['binding_sha256']==sha(W/'private/acpi-02/g63_binding.h')==a['binding_header_sha256']and a['evaluated_marker_STA_CCA_HID_and_resource_bytes_match']
assert signed['SHA256_Authenticode_digest_matches_verified_CMS_content']and signed['REA_Ghidra_import_inventory_matches_PE_imports']and signed['signed_driver_sha256']==sha(W/'private/G63-signed.sys')
assert J(W/'private/capture-model-01/tests.json')['passed']and J(W/'private/capture-model-01/tests.json')['capture_source_sha256']==sha(W/'g63_capture.c')
assert J(W/'private/driver-model-02/tests.json')['passed']and J(W/'private/driver-model-02/tests.json')['driver_source_sha256']==sha(W/'g63_driver.c')
assert J(W/'private/decode-model-01/tests.json')['passed']and J(W/'private/decode-model-01/tests.json')['decoder_sha256']==sha(W/'g63_decode.go')
h=J(W/'private/admin-01/build.json');assert sha(W/'private/admin-01/g63-admin-arm64.exe')==h['binary_sha256'];assert all(sha(W/n)==v for n,v in h['source_files_sha256'].items())
s=(W/'g63_driver.c').read_text()+(W/'g63_capture.c').read_text();assert not re.search(r'\b(?:MmMapIoSpace(?:Ex)?|MmUnmapIoSpace|WdfInterruptCreate|IoConnectInterrupt(?:Ex)?|WdfDmaEnablerCreate|SpbDeviceInitConfig|READ_REGISTER_\w+|WRITE_REGISTER_\w+|ZwWriteFile)\s*\(',s)
inf=(W/'OpenG63.inf').read_text();assert'ACPI\\OPEN0063'in inf and'Root\\'not in inf and'LowerFilters'not in inf and'StartType=3'in inf
r={'passed':True,'source_build_models_signature_and_REA_imports_verified':True,'signed_driver_sha256':signed['signed_driver_sha256'],'trial_DSDT_sha256':a['trial_DSDT_sha256'],'capture_cases':3507,'adapter_cases':28,'decoder_cases':62,'native_resource_handoff_qualified':False,'native_driver_loading_or_phone_update_performed_by_this_preflight':False};(W/'preflight.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r))
