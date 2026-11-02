"""Build the guarded user-mode devnode helper; no native control occurs here."""
from pathlib import Path
import argparse,hashlib,json,os,subprocess

W=Path(__file__).resolve().parent;p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args()
out=a.output.resolve();assert not out.exists();out.mkdir(parents=True)
files=[W/n for n in ['g66_policy.go','g66_authorization.go','g66_pnp_windows.go']]
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
inputs={p.name:sha(p)for p in files}
q=subprocess.run(['go','run',str(files[0]),str(files[1]),str(W/'g66_cases.go')],capture_output=True,text=True)
assert not q.returncode,(q.stdout,q.stderr)
t=json.loads(q.stdout);assert t['passed']and t['native_operations']==0
(out/'tests.json').write_text(json.dumps(t,indent=2)+'\n')
version=subprocess.check_output(['go','version'],text=True).strip();assert 'go1.26.4 'in version
exe=out/'g66-pnp-arm64.exe';env=dict(os.environ,GOOS='windows',GOARCH='arm64',CGO_ENABLED='0')
q=subprocess.run(['go','build','-trimpath','-buildvcs=false','-ldflags=-s -w -buildid=','-gcflags=-m','-o',str(exe),*[str(p)for p in files]],env=env,capture_output=True,text=True)
assert not q.returncode,(q.stdout,q.stderr)
assert inputs=={p.name:sha(p)for p in files}
escape=[s for s in q.stderr.splitlines()if'moved to heap:'in s]
assert any('moved to heap: dn'in s for s in escape)and any('moved to heap: status'in s for s in escape)
m={'Go_version':version,'target':'windows/arm64','source_sha256':inputs,'binary_sha256':sha(exe),'bytes':exe.stat().st_size,'guard_cases':t['cases'],'compiler_pointer_escape_lines':escape,'native_operations':0}
(out/'build.json').write_text(json.dumps(m,indent=2)+'\n');print(json.dumps(m),flush=True)
