"""Build one native Windows ARM64 helper with deterministic Go settings."""
from pathlib import Path
import argparse,hashlib,json,os,subprocess
p=argparse.ArgumentParser();p.add_argument('--name',choices=['receiver','admin','process','child','cleanup'],required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True);W=Path(__file__).resolve().parent;src=W/('g55_'+a.name+'.go');out=a.output/('g55-'+a.name+'-arm64.exe');env=dict(os.environ,GOOS='windows',GOARCH='arm64',CGO_ENABLED='0')
q=subprocess.run(['go','build','-trimpath','-buildvcs=false','-ldflags=-s -w -buildid=','-o',str(out.resolve()),str(src.resolve())],env=env,capture_output=True,text=True);assert not q.returncode,q.stderr
v={'source':src.name,'source_sha256':hashlib.sha256(src.read_bytes()).hexdigest(),'binary_sha256':hashlib.sha256(out.read_bytes()).hexdigest(),'bytes':out.stat().st_size,'Go_version':subprocess.check_output(['go','version'],text=True).strip(),'target':'windows/arm64','helper':a.name,'native_operations_by_builder':0};(a.output/'build.json').write_text(json.dumps(v,indent=2)+'\n');print(json.dumps(v))
