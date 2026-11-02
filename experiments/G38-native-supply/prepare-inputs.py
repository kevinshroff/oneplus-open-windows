"""Bind G38 to G37's qualified firmware/state and retained G33 power evidence."""
from pathlib import Path
import argparse,hashlib,json
p=argparse.ArgumentParser();p.add_argument('--inputs',required=True,type=Path);p.add_argument('--output',required=True,type=Path);a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True);G=a.inputs;sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();j=lambda p:json.loads(p.read_text())
h=G/'engine-G37/private/inputs/g37_binding.h';b=h.with_name('binding.json');assert sha(h)=='04e69edd3f19a36b2cd617e0d2a4231845cbf40af77658bdc025efb521192b9e'and sha(b)=='f01349972fd2578176fea8875410f3ef0a3ae23b3246238a172bde555fb43110'
(a.output/'g38_binding.h').write_text(h.read_text().replace('G37','G38'));(a.output/'binding.json').write_bytes(b.read_bytes())
current=j(G/'engine-G37/native-qualification.json');assert current['phase']=='unloaded_service_and_endpoint_absent_control8CPUs'and all(x['pmic_status_raw']==0x43 and x['configuration']==[8,7,0,0,7,7,0,0]for x in current['captures'].values())
old=j(G/'avdd-G33/trial/native-result.json');assert not old['success']and old['needs_recovery']and old['enabled_pmic']['status']==0xc7 and old['restored_pmic']['status']==0x43
assert old['preflight_client_raw']==old['restored_client_raw']=={'voltage':1800,'mode':7,'enable':0x80000000}
(a.output/'binding-proof.json').write_text(json.dumps({'generated_header_sha256':sha(a.output/'g38_binding.h'),'previous_header_sha256':sha(h),'previous_native_sha256':sha(G/'engine-G37/native-qualification.json'),'historical_G33_sha256':sha(G/'avdd-G33/trial/native-result.json'),'historical_failure_not_rewritten':True,'required_raw_statuses':[67,199,67],'fixed_platform_words':50},indent=2)+'\n')
print(json.dumps({'binding_reproduced':True,'required_statuses':[67,199,67]}))
