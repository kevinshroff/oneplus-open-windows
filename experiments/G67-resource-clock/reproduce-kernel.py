"""Rebuild the ACPI/clock/adapter from clean copied source, without native I/O."""
from pathlib import Path
import argparse,hashlib,json,shutil,subprocess,sys
p=argparse.ArgumentParser();p.add_argument('--inputs',type=Path,required=True);p.add_argument('--original',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True)
W=Path(__file__).resolve().parent;B=a.inputs.resolve();out=a.output.resolve();src=out/'source';src.mkdir();sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
names=['g67_clock.c','g67_clock.h','g67_protocol.h','g67_driver.c','test-clock.c','test-clock.py','test-driver.c','test-driver.py','source-map.py','build-acpi.py','compile-driver.py']
for n in names:shutil.copyfile(W/n,src/n)
shutil.copytree(W/'model-headers',src/'model-headers')
def run(script,*args):
 q=subprocess.run([sys.executable,str(src/script),*[str(x)for x in args]],capture_output=True,text=True);assert not q.returncode,(q.stdout,q.stderr)
run('source-map.py','--inputs',B,'--clock-ids',B/'clock-owner-G67/private/gcc-kalama-binding.h','--output',out/'source-map.json')
assert (out/'source-map.json').read_bytes()==(W/'source-map.json').read_bytes()
run('build-acpi.py','--original',a.original.resolve(),'--source-map',out/'source-map.json','--output',out/'acpi')
for n in ['acpitabl.dat','expected-crs.bin','g67_binding.h']:assert (out/'acpi'/n).read_bytes()==(W/'private/acpi-02'/n).read_bytes()
run('test-clock.py','--output',out/'clock-model')
run('test-driver.py','--binding',out/'acpi','--output',out/'driver-model')
run('compile-driver.py','--kits',B/'spi-G27/private/wdk-extraction-reproduced','--msvc',B/'spi-G27/private/msvc-include','--binding',out/'acpi','--output',out/'objects')
old=json.loads((W/'private/compile-03/compile.json').read_text());new=json.loads((out/'objects/compile.json').read_text());assert old['objects']==new['objects']and old['headers']==new['headers']and old['binding_sha256']==new['binding_sha256']
for row in old['objects']:assert (out/'objects'/row['object']).read_bytes()==(W/'private/compile-03'/row['object']).read_bytes()
clock=json.loads((out/'clock-model/tests.json').read_text());driver=json.loads((out/'driver-model/tests.json').read_text());assert clock['cases']==300 and driver['cases']==47
assert sha(out/'driver-model/MODEL-NOT-NATIVE.bin')==sha(W/'private/driver-model-04/MODEL-NOT-NATIVE.bin')
r={'passed':True,'source_sha256':{n:sha(src/n)for n in names},'FDT_reader_sha256':sha(B/'fdt-analysis/fdtree.py'),'source_map_byte_identical':True,'ACPI_CRS_and_binding_byte_identical':True,'ARM64_objects_byte_identical':True,'objects':new['objects'],'clock_cases':clock['cases'],'actual_adapter_cases':driver['cases'],'model_packet_sha256':sha(out/'driver-model/MODEL-NOT-NATIVE.bin'),'native_operations':0,'native_clock_behavior_qualified':False};(out/'source-reproduction.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r))
