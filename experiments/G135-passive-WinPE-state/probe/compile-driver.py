"""Compile this fixed observer with the previously pinned ARM64 WDK headers."""
from pathlib import Path
import argparse,hashlib,json,struct,subprocess
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args()
w=Path(__file__).resolve().parent;o=a.output.resolve();assert not o.exists();o.mkdir(parents=True)
baseline=w.parents[1]/'charging-G108/probe'
b=json.loads((baseline/'private/compile-03/compile.json').read_text())
args=[s.replace(str(baseline),str(w)).replace('g108_driver','g135_driver')for s in b['argv']];args[-1]=str(o/'g135_driver.obj')
r=subprocess.run(args,capture_output=True,text=True);(o/'compiler.txt').write_text(r.stdout+r.stderr);assert r.returncode==0,r.stdout+r.stderr
obj=o/'g135_driver.obj';data=obj.read_bytes();assert struct.unpack_from('<H',data)[0]==0xaa64
obj.write_bytes(data[:4]+b'\0'*4+data[8:])
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
report={'passed':True,'argv':args,'object_sha256':sha(obj),'bytes':obj.stat().st_size,
        'sources':{n:sha(w/n)for n in ['g135_driver.c','g135_binding.h','g135_protocol.h','g135_select.h','guard-and-status.inc','lifecycle.inc']},'native_operations':0}
(o/'compile.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({k:v for k,v in report.items()if k not in ['argv','sources']}))
