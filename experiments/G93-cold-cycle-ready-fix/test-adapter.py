"""Actual native adapter against explicit API/MMIO contract models."""
from pathlib import Path
import argparse,hashlib,json,struct,subprocess
p=argparse.ArgumentParser();p.add_argument('--binding',type=Path,required=True);p.add_argument('--native-evidence',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True);W=Path(__file__).resolve().parent;exe=a.output/'adapter-model'
b=(a.native_evidence/'power.bin').read_bytes();assert hashlib.sha256(b).hexdigest()=='3c5379882f062dad5c5534002de364b02278ecf4db85d3114861983d152ab058';u=lambda i:struct.unpack_from('<I',b,i)[0];addresses=set()
assert u(96)==3 and u(100)==1
for at in [164+i*3264 for i in range(3)]+[29540]:
 start,count=(at+192,u(at+24))if at<29540 else(at+84,u(at+80))
 for i in range(count):
  kind,addr,value=struct.unpack_from('<III',b,start+i*12)
  if kind==1:addresses.add(addr)
native=json.loads((a.native_evidence/'native-evidence.json').read_text());guards=[native['snapshot_before']['values'][i]for i in [38,39,42,43,46,47,48,49]];assert [x['value']for x in guards]==list(struct.unpack_from('<8I',b,34400))
addresses.update(int(x['address'],16)if isinstance(x['address'],str)else x['address']for x in guards);assert len(addresses)==45
contract=a.output/'observed-G72-read-contract.bin';contract.write_bytes(struct.pack('<45I',*sorted(addresses)))
names=['test-adapter.c','g93_rsc.c','g93_observer.c','g93_power.c','g93_adapter_policy.c']
q=subprocess.run(['clang','-std=c11','-Wall','-Wextra','-Werror','-Wno-multichar','-O1','-g','-fsanitize=address,undefined','-fno-omit-frame-pointer','-I'+str(W/'model-headers'),'-I'+str(W),'-I'+str(a.binding),*[str(W/n)for n in names],'-o',str(exe)],capture_output=True,text=True);(a.output/'compiler.txt').write_text(q.stdout+q.stderr);assert not q.returncode,(q.stdout,q.stderr)
q=subprocess.run([str(exe),str(a.output/'MODEL-NOT-NATIVE.bin'),str(contract)],capture_output=True,text=True);assert not q.returncode and not q.stderr,(q.stdout,q.stderr);r=json.loads(q.stdout);r.update(source_sha256={n:hashlib.sha256((W/n).read_bytes()).hexdigest()for n in names+['test-power.c','g93_driver.c','g93_protocol.h','g93_power.h','g93_observer.h','g93_adapter_policy.h']},model_headers_sha256={p.name:hashlib.sha256(p.read_bytes()).hexdigest()for p in(W/'model-headers').glob('*.h')},binding_sha256=hashlib.sha256((a.binding/'g93_binding.h').read_bytes()).hexdigest(),fixture_sha256=hashlib.sha256((a.output/'MODEL-NOT-NATIVE.bin').read_bytes()).hexdigest(),read_contract_sha256=hashlib.sha256(contract.read_bytes()).hexdigest(),G72_capture_sha256=hashlib.sha256(b).hexdigest(),sanitizers=['AddressSanitizer','UndefinedBehaviorSanitizer'],limits=['WDF, kernel APIs, MMIO behavior and the combined cold lease and electrical settling are modeled. This is not native driver admission or hardware operation.','Wide string content is modeled using host wchar_t; actual Windows UTF16/ARM64 declarations are checked by the separate pinned WDK compile.']);(a.output/'tests.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r))
