"""Build pure Windows path checks from the actual production predicate."""
from pathlib import Path
import argparse,hashlib,json,os,re,subprocess
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();W=Path(__file__).resolve().parent;B=W.parent/'stream-G59';assert not a.output.exists();a.output.mkdir(parents=True);sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
source=(B/'g59_receiver.go').read_text();m=re.search(r'if !(strings.EqualFold\(filepath.Clean\(adminPath\), filepath.Join\(dir, "G59-admin.exe"\)\))',source);assert m
main=r'''package main
import("encoding/json";"os";"strings";"path/filepath")
func parent(dir,adminPath string)bool{return __PARENT__}
func main(){token:="00000000000000000000000000000000";d:=idleCaptureDirectory;b:=filepath.Join(d,"G59-receiver-"+token);r:=b+"-ready.json";p:=b+"-power.bin";n:=0;check:=func(got,want bool){if got!=want{panic("Windows path expectation differs")};n++}
 check(exactEvidencePaths(r,p,token,d),true)
 check(exactEvidencePaths(strings.ToLower(r),strings.ToLower(p),token,d),true)
 check(exactEvidencePaths(r,p,strings.Repeat("a",32),d),false)
 check(exactEvidencePaths(r,p,token,d+"-other"),false)
 check(exactEvidencePaths(r,p,token,`X:\OpenG17\payloads`),false)
 check(exactEvidencePaths(r,p,token,activeCaptureDirectory),false)
 check(exactEvidencePaths(p,r,token,d),false)
 check(exactEvidencePaths(r,p+"x",token,d),false)
 check(exactEvidencePaths(r,p,token[:31],d),false)
 check(exactEvidencePaths(r,p,strings.ToUpper(token),d),false)
 check(exactEvidencePaths(r,p,strings.Repeat("../",10)+"ab",d),false)
 check(exactEvidencePaths(`\\?\`+r,p,token,d),false)
 check(exactEvidencePaths(filepath.Join(d,"nested","..",filepath.Base(r)),p,token,d),true)
 check(exactEvidencePaths(filepath.Join(d,"..",filepath.Base(r)),p,token,d),false)
 check(parent(d,filepath.Join(d,"G59-admin.exe")),true)
 check(parent(d,filepath.Join(d,"G60-idle-admin.exe")),false)
 check(parent(d,filepath.Join(d,"..","G59-admin.exe")),false)
 check(parent(d,strings.ToLower(filepath.Join(d,"G59-admin.exe"))),true)
 json.NewEncoder(os.Stdout).Encode(map[string]any{"passed":true,"cases":n,"actual_production_evidence_predicate":true,"actual_G59_receiver_parent_predicate":true,"MMIO_or_driver_requests":0})
}
'''.replace('__PARENT__',m.group(1));g=a.output/'main.go';g.write_text(main);s=a.output/'g59_paths.go';s.write_bytes((W/'g59_paths.go').read_bytes());out=a.output/'g60-path-probe-arm64.exe';env=dict(os.environ,GOOS='windows',GOARCH='arm64',CGO_ENABLED='0');q=subprocess.run(['go','build','-trimpath','-buildvcs=false','-ldflags=-s -w -buildid=','-o',str(out.resolve()),str(s.resolve()),str(g.resolve())],env=env,capture_output=True,text=True);assert not q.returncode,q.stderr
v={'probe_sha256':sha(out),'predicate_source_sha256':sha(W/'g59_paths.go'),'original_receiver_source_sha256':sha(B/'g59_receiver.go'),'new_native_probe_not_yet_run':True};(a.output/'build.json').write_text(json.dumps(v,indent=2)+'\n');print(json.dumps(v))
