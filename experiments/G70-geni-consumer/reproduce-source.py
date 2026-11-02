"""Copy source, regenerate AML, replay models, and reproduce all ARM64 objects."""
from pathlib import Path
import argparse,hashlib,json,shutil,subprocess,sys
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();W=Path(__file__).resolve().parent;B=W.parent;out=a.output.resolve();out.mkdir(exist_ok=False);src=out/'source';src.mkdir();sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
names=['build-acpi.py','g70_clock.c','g70_clock.h','g70_protocol.h','g70_consumer.c','g70_consumer.h','g70_driver.c','g70_client_windows.c','g70_client_policy.c','g70_client_policy.h','test-clock.c','test-clock.py','test-consumer.c','test-consumer.py','test-driver.c','test-driver.py','test-client-policy.c','test-client-policy.py','compile-driver.py','compile-client.py']
for n in names:shutil.copyfile(W/n,src/n)
shutil.copytree(W/'model-headers',src/'model-headers')
def run(name,*args):
 q=subprocess.run([sys.executable,str(src/name),*[str(x) for x in args]],capture_output=True,text=True);assert not q.returncode,(name,q.stdout,q.stderr)
run('build-acpi.py','--original',B/'acpi-G20/private/DSDT-native.bin','--inputs',B,'--output',out/'binding')
for n in ['acpitabl.dat','expected-crs.bin','g70_binding.h','build.json']:assert (W/'private/acpi-01'/n).read_bytes()==(out/'binding'/n).read_bytes(),n
run('test-clock.py','--output',out/'clock-model','--native-fixture',B/'native-clock-G68/private/G67-native-cycle.bin')
run('test-consumer.py','--output',out/'consumer-model')
run('test-driver.py','--binding',out/'binding','--output',out/'driver-model')
run('test-client-policy.py','--binding',out/'binding','--fixture',out/'driver-model/MODEL-NOT-NATIVE.bin','--output',out/'client-policy')
sdk=B/'clock-owner-G67/private/user-sdk-01';sdkmeta=json.loads((sdk/'extraction.json').read_text())
for row in sdkmeta['files']:assert sha(sdk/row['output'])==row['sha256']
common=['--kits',B/'spi-G27/private/wdk-extraction-reproduced','--msvc',B/'spi-G27/private/msvc-include','--binding',out/'binding']
run('compile-driver.py',*common,'--output',out/'kernel-objects')
run('compile-client.py',*common,'--user-sdk',sdk,'--output',out/'client-objects')
for original,new in [('compile-01','kernel-objects'),('client-objects-01','client-objects')]:
 old=json.loads((W/'private'/original/'compile.json').read_text());fresh=json.loads((out/new/'compile.json').read_text());assert old['objects']==fresh['objects'] and old['headers']==fresh['headers'] and old['binding_sha256']==fresh['binding_sha256']
 for row in old['objects']:assert (W/'private'/original/row['object']).read_bytes()==(out/new/row['object']).read_bytes()
assert sha(out/'driver-model/MODEL-NOT-NATIVE.bin')==sha(W/'private/driver-model-01/MODEL-NOT-NATIVE.bin')
models=[json.loads((out/n/'tests.json').read_text()) for n in ['clock-model','consumer-model','driver-model','client-policy']];assert all(m['passed'] for m in models)
r={'passed':True,'source_sha256':{n:sha(src/n) for n in names},'regenerated_binding_and_models_identical':True,'ARM64_objects_byte_identical':True,'SDK_files_rehashed':len(sdkmeta['files']),'model_cases':[m['cases'] for m in models],'native_operations':0};(out/'source-reproduction.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({k:v for k,v in r.items() if k!='source_sha256'}))
