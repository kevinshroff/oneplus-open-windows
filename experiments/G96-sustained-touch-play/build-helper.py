"""Build one native Windows ARM64 helper with deterministic Go settings."""
from pathlib import Path
import argparse,hashlib,json,os,subprocess
p=argparse.ArgumentParser();p.add_argument('--name',choices=['receiver','admin','process','child','cleanup'],required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True);W=Path(__file__).resolve().parent;src=W/('g96_'+a.name+'.go');out=a.output/('g96-'+a.name+'-arm64.exe');env=dict(os.environ,GOOS='windows',GOARCH='arm64',CGO_ENABLED='0')
sources=[src,W/'g96_hwdecode.go',W/'g96_hwclient.go',W/'g96_fields.go',W/'g96_session.go']if a.name=='admin'else[src];
if a.name!='process':sources.append(W/'g96_fullos.go')
source_hashes={x.name:hashlib.sha256(x.read_bytes()).hexdigest()for x in sources}
q=subprocess.run(['go','build','-trimpath','-buildvcs=false','-ldflags=-s -w -buildid=','-o',str(out.resolve()),*[str(x.resolve())for x in sources]],env=env,capture_output=True,text=True);assert not q.returncode,q.stderr
assert source_hashes=={x.name:hashlib.sha256(x.read_bytes()).hexdigest()for x in sources},'Source changed during build'
v={'source_files_sha256':source_hashes,'source':src.name,'source_sha256':hashlib.sha256(src.read_bytes()).hexdigest(),'binary_sha256':hashlib.sha256(out.read_bytes()).hexdigest(),'bytes':out.stat().st_size,'Go_version':subprocess.check_output(['go','version'],text=True).strip(),'target':'windows/arm64','helper':a.name,'native_operations_by_builder':0};(a.output/'build.json').write_text(json.dumps(v,indent=2)+'\n');print(json.dumps(v))
