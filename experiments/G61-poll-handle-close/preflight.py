"""Check the qualified immutable dependency chain; no native operations."""
from pathlib import Path
import hashlib,json,subprocess,sys
W=Path(__file__).resolve().parent;B=W.parent/'contact-cancel-G60';K=W.parent/'stream-G59';J=lambda p:json.loads(p.read_text());sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
subprocess.run([sys.executable,str(B/'preflight.py')],check=True,capture_output=True,text=True)
prior=J(B/'native-qualification-idle-stop-v2.json');assert prior['phase']=='owned_input_devices_packages_service_removed_original_baseline_restored'
assert J(B/'idle-poll-audit.json')['passed'] and J(B/'private/reproduction-01/source-reproduction.json')['passed']
for name,h in J(W/'workflow-seal.json')['files'].items():assert sha(W/name)==h,name
c=J(B/'private/idle-admin-02/build.json');assert c['binary_sha256']=='720e0940dadaffe346c4bdc78369e26a85ae4f7dd41b6105b0249b3dfa930c2e'
assert sha(B/'private/idle-admin-02/g60-admin-idle-arm64.exe')==c['binary_sha256']
assert sha(K/'private/G59-signed.sys')=='dd0699a33c5b04b36b6df3957cf3f6c83b77f9844c1391eed165fff9f272dc74'
r={'passed':True,'native_operations':0,'G60_idle_stop_audit_passed':True,'G59_kernel_G60_caller_unchanged':True,'caller_sha256':c['binary_sha256'],'kernel_sha256':sha(K/'private/G59-signed.sys'),'distinct_native_mode':'owning_handle_close_during_idle_polling','active_contact_or_PnP_power_qualified':False};(W/'preflight.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r))
