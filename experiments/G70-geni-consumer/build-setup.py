"""Build the RAM-only setup helper and pure guards, without native operations."""
from pathlib import Path
import argparse,hashlib,json,os,subprocess

p=argparse.ArgumentParser()
p.add_argument('--output',type=Path,required=True)
p.add_argument('--package-manifest',type=Path)
a=p.parse_args();W=Path(__file__).resolve().parent
manifest=a.package_manifest or W/'private/package.json'
if a.package_manifest is None and not manifest.is_file():
    manifest=W.parents[1]/'evidence/G70/package-manifest.json'
assert not a.output.exists();a.output.mkdir(parents=True)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(manifest)=='a380536307155d4c9362884ad31aad11a396640d53ac057c9a6978c07050959a'
q=subprocess.run(['go','run',str(W/'g70_policy.go'),str(W/'g70_policy_cases.go')],capture_output=True,text=True)
assert not q.returncode,(q.stdout,q.stderr)
tests=json.loads(q.stdout);assert tests['passed']
(a.output/'policy-tests.json').write_text(json.dumps(tests,indent=2)+'\n')
files=[W/'g70_policy.go',W/'g70_setup_windows.go']
before={p.name:sha(p)for p in files}
version=subprocess.check_output(['go','version'],text=True).strip();assert'go1.26.4 'in version
out=a.output/'g70-setup-arm64.exe';env=dict(os.environ,GOOS='windows',GOARCH='arm64',CGO_ENABLED='0')
q=subprocess.run(['go','build','-trimpath','-buildvcs=false','-ldflags=-s -w -buildid=','-gcflags=-m','-o',str(out.resolve()),*[str(p.resolve())for p in files]],env=env,capture_output=True,text=True)
assert not q.returncode,(q.stdout,q.stderr)
assert before=={p.name:sha(p)for p in files}
heap=[s for s in q.stderr.splitlines()if'moved to heap:'in s]
assert any('moved to heap: dn'in s for s in heap)and any('moved to heap: reboot'in s for s in heap)
m={'source_files_sha256':before,'binary_sha256':sha(out),'bytes':out.stat().st_size,'Go_version':version,'target':'windows/arm64','package_manifest_sha256':sha(manifest),'RAM_guard_policy_cases':tests['cases'],'compiler_pointer_escape_lines':heap,'native_operations':0}
(a.output/'build.json').write_text(json.dumps(m,indent=2)+'\n');print(json.dumps(m))
