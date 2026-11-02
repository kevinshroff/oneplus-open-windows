"""Rebuild the native query helper and verify original SDK C/Go contracts."""
from pathlib import Path
import argparse,json,subprocess,sys
p=argparse.ArgumentParser();p.add_argument('--evidence',type=Path,required=True);p.add_argument('--header',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();W=Path(__file__).resolve().parent;assert not a.output.exists();a.output.mkdir(parents=True)
def run(name,*args):
 q=subprocess.run([sys.executable,str(W/name),*map(str,args)],capture_output=True,text=True);assert not q.returncode,(q.stdout,q.stderr)
run('build.py','--output',a.output/'helper');actual=json.loads((a.output/'helper/build.json').read_text());expected=json.loads((a.evidence/'helper-build.json').read_text())
for key in ['source_files_sha256','binary_sha256','bytes','Go_version','target','API_calls','heap_pointer_lifetime_verified']:assert actual[key]==expected[key],key
run('test-codec.py','--header',a.header,'--output',a.output/'codec');t=json.loads((a.output/'codec/tests.json').read_text());old=json.loads((a.evidence/'codec-tests.json').read_text())
for key in ['cases','original_SDK_header_sha256','ARM64_C_ABI_static_assertions','C_generated_fixture_sha256','decoder_source_sha256']:assert t[key]==old[key],key
v={'passed':True,'native_helper_rebuild_byte_identical':True,'helper_sha256':actual['binary_sha256'],'decoder_RLE_cases':t['cases'],'ARM64_C_ABI_assertions':t['ARM64_C_ABI_static_assertions'],'native_operations':0};(a.output/'source-reproduction.json').write_text(json.dumps(v,indent=2)+'\n');print(json.dumps(v))
