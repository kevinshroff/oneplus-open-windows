"""Reproduce one G51 Windows/ARM64 helper without executing it."""
from pathlib import Path
import argparse,hashlib,json,os,subprocess
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--source',type=Path,required=True)
p.add_argument('--output',type=Path,required=True)
a=p.parse_args();assert a.source.is_file() and not a.output.exists()
a.output.mkdir(parents=True);exe=a.output/'helper-arm64.exe'
subprocess.run(['go','build','-trimpath','-buildvcs=false','-ldflags=-s -w -buildid=','-o',str(exe.resolve()),str(a.source.resolve())],env=dict(os.environ,GOOS='windows',GOARCH='arm64',CGO_ENABLED='0'),check=True,capture_output=True,text=True)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
r={'source_sha256':sha(a.source),'binary_sha256':sha(exe),'bytes':exe.stat().st_size,'target':'windows/arm64','Go_version':subprocess.check_output(['go','version'],text=True).strip(),'native_commands_submitted':0}
(a.output/'build.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r))
