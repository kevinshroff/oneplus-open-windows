"""Check exact current models, binding, namespace and restricted adapter delta."""
from pathlib import Path
import hashlib,json,re
W=Path(__file__).resolve().parent;P=W/'private';B=W.parent/'clock-owner-G67'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
models={n:json.loads((P/n/'tests.json').read_text())for n in ['clock-model-01','driver-model-01','client-policy-02']}
assert [m['cases']for m in models.values()]==[4704,47,250]
for m in models.values():
 assert m['passed']and m['native_operations']==0
 for n,h in m.get('source_sha256',{}).items():assert sha(W/n)==h,n
assert models['driver-model-01']['driver_source_sha256']==sha(W/'g69_driver.c')
assert models['driver-model-01']['model_packet_sha256']==models['client-policy-02']['fixture_sha256']==sha(P/'driver-model-01/MODEL-NOT-NATIVE.bin')
assert models['clock-model-01']['worst_case_read_calls']==63 and models['clock-model-01']['worst_case_trace_rows']==83
binding=P/'acpi-binding/g69_binding.h'
table=bytes(int(x,16)for x in re.findall(r'0x([0-9a-f]{2})',binding.read_text()))
assert len(table)==742 and hashlib.sha256(table).hexdigest()=='1682de06510a8dc8f1d82a10be035e3ac9e8ecbd5b116f0ad160d8f43e1832f1'
assert models['driver-model-01']['binding_sha256']==sha(binding)
for c in ['compile-01','client-objects-01']:
 m=json.loads((P/c/'compile.json').read_text());assert m['binding_sha256']==sha(binding)
 for n,h in m['headers'].items():assert sha(W/n)==h
 for row in m['objects']:assert sha(W/row['source'])==row['source_sha256']and sha(P/c/row['object'])==row['sha256']
def renamed(s):
 return s.replace('G67','G69').replace('g67','g69').replace('0x314b4c433736504f','0x314b4c433936504f').replace('32af76b23967','32af76b23969').replace('0x76,0xb2,0x39,0x67','0x76,0xb2,0x39,0x69').replace('0x002267c4','0x002267d4').replace('0x0022e7c8','0x0022e7d8').replace('0x9f1','0x9f5').replace('0x9f2','0x9f6')
assert renamed((B/'g67_driver.c').read_text())==(W/'g69_driver.c').read_text()
assert renamed((B/'g67_client_windows.c').read_text())==(W/'g69_client_windows.c').read_text()
inf=(W/'OpenG69.inf').read_text();assert r'ACPI\OPEN0067'in inf and 'OPEN0069'not in inf and 'ServiceBinary=%13%\\OpenG69.sys'in inf and 'DriverVer=10/22/2026,0.0.69.0'in inf
if(P/'package.json').exists():
 m=json.loads((P/'package.json').read_text());assert m['hardware_id']==r'ACPI\OPEN0067'and m['interface_guid']=='2f1df03e-a4ab-4e14-a587-32af76b23969'
 assert m['files']['OpenG69.sys']==sha(P/'G69-signed.sys')and m['trial_DSDT_sha256']==hashlib.sha256(table).hexdigest()
r={'passed':True,'model_cases':[4704,47,250],'existing_native_qualified_742byte_table_reused':True,'adapter_and_native_client_delta_only_new_G69_names_interface_magic_IOCTLs':True,'hardware_id':r'ACPI\OPEN0067','native_G69_admission_or_cycle_qualified':False}
(W/'preflight.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r))
