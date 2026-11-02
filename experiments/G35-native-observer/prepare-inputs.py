"""Bind G35 to the exact G34 firmware/register binding and last native capture."""
from pathlib import Path
import argparse,hashlib,json
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--inputs',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True)
G=a.inputs;old=G/'platform-G34';sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
header=old/'private/inputs/g34_binding.h';binding=old/'private/inputs/binding.json';native=old/'native-qualification.json'
assert sha(header)=='146df73f2d1adc754dd85f9440c7ec17f2cca70b7f546a641b23b7aa9e539030'
assert sha(binding)=='f01349972fd2578176fea8875410f3ef0a3ae23b3246238a172bde555fb43110'
n=json.loads(native.read_text());b=json.loads(binding.read_text());assert n['phase']=='cycle2_unloaded_service_and_endpoint_absent_control8CPUs'
assert n['phone_session']=='00000000000000000000000000000000'
values=n['cycle2']['snapshots'][-1]['values'];assert len(values)==50
assert [int(x['address'],16)for x in values]==[x['address']for x in b['fields']]
assert values==n['cycle2']['snapshots'][0]['values']==n['cycle1']['snapshots'][0]['values']==n['cycle1']['snapshots'][1]['values']
h=header.read_text().replace('G34','G35')+'static const ULONG G35ExpectedValues[G35_REGISTER_COUNT]={'+','.join('0x%xu'%x['value']for x in values)+'};\n'
(a.output/'g35_binding.h').write_text(h);(a.output/'binding.json').write_bytes(binding.read_bytes())
obs=G/'avdd-G33/independent-PMIC-post.json';assert sha(obs)=='b52c14d6a064aa35dd7d870a42e8aff359abd0cfac0372e15b125d4c9a27d6b3'
proof={'G34_native_state_sha256':sha(native),'G34_generated_header_sha256':sha(header),'G34_binding_sha256':sha(binding),'G33_observer_capture_sha256':sha(obs),'expected_50_values':values,'observer_pages':[hex(x)for x in [0xc400000,0xc402000,0xc42d000,0xc440000,0xc441000,0xc445000]],'observer_read_command_addresses':['0xc440ea0','0xc441220','0xc4456e0'],'read_commands_per_capture':5,'maximum_captures_per_driver_load':2,'PMIC_configuration_writes':0,'fixed_register_writes':0}
(a.output/'observer-binding.json').write_text(json.dumps(proof,indent=2)+'\n');print(json.dumps({'fixed_baseline':len(values),'native_target_access':False}))
