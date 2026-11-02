"""Pin the unchanged qualified G59 kernel and separately compiled idle caller."""
from pathlib import Path
import hashlib,json,subprocess,sys
W=Path(__file__).resolve().parent;B=W.parent/'stream-G59';J=lambda p:json.loads(p.read_text());sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
subprocess.run([sys.executable,str(B/'preflight.py')],check=True,capture_output=True,text=True)
assert J(B/'idle-audit.json')['passed']and J(B/'native-qualification-idle.json')['phase']=='owned_input_devices_packages_service_removed_original_baseline_restored'
assert sha(W/'private/G59-signed.sys')==sha(B/'private/G59-signed.sys')=='dd0699a33c5b04b36b6df3957cf3f6c83b77f9844c1391eed165fff9f272dc74'
for name in ['G59-public.cer','OpenG59.cat','G59Vhf.cat','package.json','vhf-package.json']:assert sha(W/'private'/name)==sha(B/'private'/name)
for name in ['OpenG59.inf','G59Vhf.inf']:assert sha(W/name)==sha(B/name)
for name in ['g59_admin.go','g59_hwdecode.go','g59_fields.go','g59_session.go']:assert sha(W/name)==sha(B/name)
m=J(W/'private/idle-admin-02/build.json');assert m['cancellation_input_expectation']=='idle'and sha(W/'private/idle-admin-02/g60-admin-idle-arm64.exe')==m['binary_sha256']
for name,h in m['source_files_sha256'].items():assert sha(W/name)==h
p=J(W/'private/policy-02/tests.json');assert p['passed']and p['policy_source_sha256']==sha(W/'g59_cancel.go')
path=J(W/'native-path-probe.json');assert path['phase']=='actual_Windows_path_semantics_passed'and path['predicate_source_sha256']==sha(W/'g59_paths.go')
v={'passed':True,'native_path_cases':18,'unchanged_G59_kernel_sha256':sha(W/'private/G59-signed.sys'),'distinct_idle_caller_sha256':m['binary_sha256'],'policy_cases':p['cases'],'original_G59_receiver_and_child_cleanup_reused':True,'no_new_MMIO_policy_or_code':True,'native_G60_idle_poll_cancellation_qualified_by_this_preflight':False,'native_active_contact_cancel_qualified':False};(W/'idle-preflight.json').write_text(json.dumps(v,indent=2)+'\n');print(json.dumps(v))
