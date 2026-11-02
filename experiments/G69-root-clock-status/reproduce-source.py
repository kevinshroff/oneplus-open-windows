"""Independent copied source, actual models and ARM64 objects; no phone I/O."""
from pathlib import Path
import argparse,hashlib,json,shutil,subprocess,sys
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args()
W=Path(__file__).resolve().parent;B=W.parent;out=a.output.resolve();out.mkdir(exist_ok=False)
src=out/'source';src.mkdir();bind=out/'binding';bind.mkdir()
names=['g69_clock.c','g69_clock.h','g69_protocol.h','g69_driver.c','g69_client_windows.c','g69_client_policy.c','g69_client_policy.h','test-clock.c','test-driver.c','test-client-policy.c','test-clock.py','test-driver.py','test-client-policy.py','compile-driver.py','compile-client.py']
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
for n in names:shutil.copyfile(W/n,src/n)
shutil.copytree(W/'model-headers',src/'model-headers');shutil.copyfile(W/'private/acpi-binding/g69_binding.h',bind/'g69_binding.h')
sdk=B/'clock-owner-G67/private/user-sdk-01';sdk_manifest=json.loads((sdk/'extraction.json').read_text())
for row in sdk_manifest['files']:assert sha(sdk/row['output'])==row['sha256']
def run(name,*args):
 r=subprocess.run([sys.executable,str(src/name),*[str(x)for x in args]],capture_output=True,text=True)
 assert r.returncode==0,(name,r.stdout,r.stderr)
run('test-clock.py','--output',out/'clock-model','--native-fixture',B/'native-clock-G68/private/G67-native-cycle.bin')
run('test-driver.py','--binding',bind,'--output',out/'driver-model')
run('test-client-policy.py','--fixture',out/'driver-model/MODEL-NOT-NATIVE.bin','--output',out/'client-policy')
common=['--kits',B/'spi-G27/private/wdk-extraction-reproduced','--msvc',B/'spi-G27/private/msvc-include','--binding',bind]
run('compile-driver.py',*common,'--output',out/'kernel-objects')
run('compile-client.py',*common,'--user-sdk',sdk,'--output',out/'client-objects')
objects={}
for old,new,label in [('compile-01','kernel-objects','kernel'),('client-objects-01','client-objects','client')]:
 a=json.loads((W/'private'/old/'compile.json').read_text());b=json.loads((out/new/'compile.json').read_text())
 assert a['objects']==b['objects']and a['headers']==b['headers']and a['binding_sha256']==b['binding_sha256']
 for row in a['objects']:assert (W/'private'/old/row['object']).read_bytes()==(out/new/row['object']).read_bytes()
 objects[label]=b['objects']
assert sha(out/'driver-model/MODEL-NOT-NATIVE.bin')==sha(W/'private/driver-model-01/MODEL-NOT-NATIVE.bin')
models=[json.loads((out/n/'tests.json').read_text())for n in ['clock-model','driver-model','client-policy']]
assert [m['cases']for m in models]==[4704,47,250]and all(m['passed']for m in models)
r={'passed':True,'source_sha256':{n:sha(src/n)for n in names},'unchanged_742byte_table_binding_reproduced':True,'all_selected_SDK_files_rehashed':len(sdk_manifest['files']),'SDK_manifest_sha256':sha(sdk/'extraction.json'),'ARM64_objects_byte_identical':True,'objects':objects,'model_cases':[m['cases']for m in models],'model_packet_sha256':sha(out/'driver-model/MODEL-NOT-NATIVE.bin'),'native_operations':0,'native_G69_clock_behavior_qualified':False}
(out/'source-reproduction.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({k:v for k,v in r.items()if k not in('source_sha256','objects')}),flush=True)
