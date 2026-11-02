"""Verify only fixed-resource validation and generated AML content,not PnP."""
from pathlib import Path
import argparse,hashlib,json,struct,subprocess
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();w=Path(__file__).resolve().parent;o=a.output.resolve();o.mkdir(exist_ok=False);sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest()
r=subprocess.run(['clang','-std=c11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-g','-I'+str(w/'source'),str(w/'tests/test-resources.c'),str(w/'source/resources.c'),'-o',str(o/'test-resources')],capture_output=True,text=True);(o/'compiler.txt').write_text(r.stdout+r.stderr);assert not r.returncode,r.stderr
v=json.loads(subprocess.run([str(o/'test-resources')],capture_output=True,text=True,check=True).stdout)
# iasl's actual AML must contain the complete ordered resource template once.
r=subprocess.run(['iasl','-p',str(o/'OPRES182'),str(w/'acpi/OPRES182.asl')],capture_output=True,text=True);(o/'iasl.txt').write_text(r.stdout+r.stderr);assert not r.returncode,r.stdout+r.stderr
b=(o/'OPRES182.aml').read_bytes();assert b[:4]==b'SSDT'and struct.unpack_from('<I',b,4)[0]==len(b)and sum(b)%256==0 and b'OPEN0182\0'in b
m=json.loads((w/'resource-contract.json').read_text());pattern=b''.join(bytes([0x86,9,0,int(x['write_access'])])+struct.pack('<II',x['base'],x['bytes'])for x in m['resources'])+b'\x79\x00';assert b.count(pattern)==1
v.update(AML_checksum_and_exact_20_ranges=True,AML_bytes=len(b),AML_sha256=sha(o/'OPRES182.aml'),source_sha256={str(f.relative_to(w)):sha(f)for d in ['source','tests','acpi']for f in(w/d).iterdir()if f.is_file()},limits=['Actual resource validator and compiled AML checked; WDF event/lifetime primitives not modeled or native-qualified.','No firmware publication,driver link/sign/install or register access. ProducerQualified remains false.'])
(o/'verification.json').write_text(json.dumps(v,indent=2)+'\n');print({k:v[k]for k in ['passed','actual_resource_validator_cases','AML_checksum_and_exact_20_ranges','AML_bytes','native_operations']})
