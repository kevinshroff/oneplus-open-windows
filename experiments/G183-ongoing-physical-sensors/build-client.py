"""Build the read-only ARM64 Windows status client; no native operations."""
from pathlib import Path
import argparse,hashlib,json,os,subprocess
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();w=Path(__file__).resolve().parent;o=a.output.resolve();o.mkdir(exist_ok=False)
cmd=['go','build','-trimpath','-ldflags=-buildid=','-o',str(o/'G183-status.exe'),'main_windows.go','guard_windows.go'];subprocess.run(cmd,cwd=w/'client',env=dict(os.environ,GOOS='windows',GOARCH='arm64',CGO_ENABLED='0'),check=True)
r={'passed':True,'argv':cmd,'Go_version':subprocess.check_output(['go','version'],text=True).strip(),'sources':{f.name:hashlib.sha256(f.read_bytes()).hexdigest()for f in(w/'client').iterdir()if f.is_file()},'exe_sha256':hashlib.sha256((o/'G183-status.exe').read_bytes()).hexdigest(),'native_operations':0};(o/'build.json').write_text(json.dumps(r,indent=2)+'\n');print({k:v for k,v in r.items()if k!='sources'})
