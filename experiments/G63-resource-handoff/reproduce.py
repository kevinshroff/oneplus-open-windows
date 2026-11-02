"""Rebuild the resource pilot sources/models; no host key, installation or phone."""
from pathlib import Path
import argparse,hashlib,json,subprocess,sys
p=argparse.ArgumentParser();p.add_argument('--evidence',type=Path,required=True);p.add_argument('--kits',type=Path,required=True);p.add_argument('--msvc',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();W=Path(__file__).resolve().parent;assert not a.output.exists();a.output.mkdir(parents=True);J=lambda p:json.loads(p.read_text());sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def run(name,*args):
 q=subprocess.run([sys.executable,str(W/name),*map(str,args)],capture_output=True,text=True);assert not q.returncode,(q.stdout,q.stderr)
run('build-acpi.py','--original',W/'inputs/original-G17-DSDT.bin','--source-map',a.evidence/'source-map.json','--output',a.output/'acpi');actual=J(a.output/'acpi/build.json');expected=J(a.evidence/'ACPI-build.json')
for key in ['trial_DSDT_sha256','trial_bytes','all_original_AML_body_bytes_preserved','actual_existing_header_changed_offsets','binding_header_sha256','expected_resource_sha256','evaluated_marker_STA_CCA_HID_and_resource_bytes_match']:assert actual[key]==expected[key],key
run('compile-driver.py','--kits',a.kits,'--msvc',a.msvc,'--binding',a.output/'acpi','--output',a.output/'objects');c=J(a.output/'objects/compile.json');old=J(a.evidence/'ARM64-compilation.json');assert c['objects']==old['objects']and c['headers']==old['headers']and c['binding_sha256']==old['binding_sha256']
run('test-capture.py','--output',a.output/'capture-model');cap=J(a.output/'capture-model/tests.json');assert cap['passed']and cap['fixture_sha256']==J(a.evidence/'capture-model.json')['fixture_sha256']
run('test-driver.py','--binding',a.output/'acpi','--output',a.output/'driver-model');drv=J(a.output/'driver-model/tests.json');assert drv['passed']and drv['driver_source_sha256']==J(a.evidence/'driver-model.json')['driver_source_sha256']
run('test-decode.py','--fixture',a.output/'capture-model/model-report.bin','--output',a.output/'decode-model');dec=J(a.output/'decode-model/tests.json');assert dec['passed']and dec['decoder_sha256']==J(a.evidence/'decoder-model.json')['decoder_sha256']
run('build-helper.py','--binding',a.output/'acpi','--output',a.output/'helper');h=J(a.output/'helper/build.json');prior=J(a.evidence/'helper-build.json')
for key in ['source_files_sha256','binary_sha256','bytes','Go_version','target','trial_DSDT_sha256']:assert h[key]==prior[key],key
r={'passed':True,'table_byte_identical':True,'ARM64_objects_byte_identical':len(c['objects']),'native_query_helper_byte_identical':True,'capture_sanitizer_cases':cap['cases'],'actual_adapter_sanitizer_cases':drv['cases'],'decoder_cases':dec['cases'],'native_operations':0,'native_resource_handoff_qualified':False};(a.output/'source-reproduction.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r))
