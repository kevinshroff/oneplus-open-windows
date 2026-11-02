"""Recompile the final small client from clean source and verified SDK inputs."""
from pathlib import Path
import argparse,hashlib,json,shutil,subprocess,sys
p=argparse.ArgumentParser();p.add_argument('--inputs',type=Path,required=True);p.add_argument('--user-sdk',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True)
W=Path(__file__).resolve().parent;B=a.inputs.resolve();out=a.output.resolve();src=out/'source';src.mkdir();sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
names=['g67_client_windows.c','g67_client_policy.c','g67_client_policy.h','g67_clock.c','g67_clock.h','g67_protocol.h','compile-client.py','test-client-policy.c','test-client-policy.py']
for n in names:shutil.copyfile(W/n,src/n)
sdk=a.user_sdk.resolve();extraction=json.loads((sdk/'extraction.json').read_text())
assert extraction['packages']['headers_sha256']=='5d31b38205bdd9ac761b4cb39fbbc6b7209b01c11194324afc674d7d119483a0'and extraction['packages']['ARM64_libraries_sha256']=='ac06922186fdd75e4ff1033a304ea629d7917bd0ca85e483762f8109584ccfc4'
for row in extraction['files']:assert sha(sdk/row['output'])==row['sha256'],row['output']
kernel=W/'private/kernel-reproduction-01';proof=json.loads((kernel/'source-reproduction.json').read_text());assert proof['passed']and proof['ACPI_CRS_and_binding_byte_identical']
binding=out/'binding';binding.mkdir();shutil.copyfile(kernel/'acpi/g67_binding.h',binding/'g67_binding.h')
def run(script,*args):
 q=subprocess.run([sys.executable,str(src/script),*[str(x)for x in args]],capture_output=True,text=True);assert not q.returncode,(q.stdout,q.stderr)
run('test-client-policy.py','--fixture',kernel/'driver-model/MODEL-NOT-NATIVE.bin','--output',out/'policy')
run('compile-client.py','--kits',B/'spi-G27/private/wdk-extraction-reproduced','--msvc',B/'spi-G27/private/msvc-include','--user-sdk',sdk,'--binding',binding,'--output',out/'objects')
old=json.loads((W/'private/client-objects-05/compile.json').read_text());new=json.loads((out/'objects/compile.json').read_text());assert old['objects']==new['objects']and old['headers']==new['headers']and old['binding_sha256']==new['binding_sha256']
for row in old['objects']:assert (out/'objects'/row['object']).read_bytes()==(W/'private/client-objects-05'/row['object']).read_bytes()
tests=json.loads((out/'policy/tests.json').read_text());assert tests['cases']==79
r={'passed':True,'source_sha256':{n:sha(src/n)for n in names},'all_selected_SDK_headers_and_libraries_hash_verified':True,'independently_reproduced_binding_used':True,'ARM64_objects_byte_identical':True,'objects':new['objects'],'client_policy_cases':79,'native_operations':0,'native_clock_operation_qualified':False};(out/'source-reproduction.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r))
