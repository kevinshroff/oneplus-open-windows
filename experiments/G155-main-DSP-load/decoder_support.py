"""Host-only saved-table decoder using the unchanged phone reader core."""
from pathlib import Path
import hashlib,json,os,subprocess
CORE=['report.go','dtb.go','dual.go','main_admission.go','main_payload.go','main_plan.go','scm_log.go']
RUNNER=r'''package main
import("os";"fmt";"encoding/json";"encoding/base64")
func main(){
 raw:=map[string]string{};result:=map[string]any{"ok":false}
 if len(os.Args)!=3{result["error"]="two saved table paths required";json.NewEncoder(os.Stdout).Encode(result);os.Exit(1)}
 a,e:=os.ReadFile(os.Args[1]);if e==nil{raw["OADP"]=base64.StdEncoding.EncodeToString(a)}
 b,f:=os.ReadFile(os.Args[2]);if f==nil{raw["OSER"]=base64.StdEncoding.EncodeToString(b)}
 if e==nil{e=f};if e==nil&&(len(a)>16384||len(b)>16384){e=fmt.Errorf("saved table size")}
 var r Report
 if e==nil{r,e=decodeReport(a)}
 if e==nil{var s ScmLog;s,e=decodeScmLog(b);if e==nil{r,e=bindScmLog(r,s)}}
 if e!=nil{result["error"]=e.Error();result["raw_tables_base64"]=raw;json.NewEncoder(os.Stdout).Encode(result);os.Exit(1)}
 json.NewEncoder(os.Stdout).Encode(map[string]any{"ok":true,"report":r})
}'''
def sha(data):return hashlib.sha256(data).hexdigest()
def decoder(root=None):
 w=Path(__file__).resolve().parent;r=w/'report-reader';out=Path(root)if root else w/'private/host-decoder'
 sources={n:sha((r/n).read_bytes())for n in CORE};sources['runner.go']=sha(RUNNER.encode())
 if out.exists():
  state=json.loads((out/'build.json').read_text());assert state['passed']and state['sources']==sources
  assert sha((out/'decode-saved').read_bytes())==state['exe_sha256'];return out/'decode-saved'
 out.mkdir(parents=True)
 for n in CORE:(out/n).write_bytes((r/n).read_bytes())
 (out/'runner.go').write_text(RUNNER);(out/'go.mod').write_text('module open-g155-offline-decoder\n\ngo 1.23\n')
 env=dict(os.environ,GOWORK='off',CGO_ENABLED='0');env.pop('GOOS',None);env.pop('GOARCH',None)
 q=subprocess.run(['go','build','-trimpath','-o',str((out/'decode-saved').resolve()),'.'],cwd=out,env=env,capture_output=True,text=True)
 (out/'compiler.txt').write_text(q.stdout+q.stderr);assert q.returncode==0,q.stderr
 (out/'build.json').write_text(json.dumps({'passed':True,'sources':sources,'exe_sha256':sha((out/'decode-saved').read_bytes()),'native_operations':0,'limits':['Saved-table host decoder only; no firmware API, phone command or stable-double-read claim.']},indent=2)+'\n')
 return out/'decode-saved'
def decode(exe,dsp,serial):
 q=subprocess.run([str(Path(exe).resolve()),str(Path(dsp).resolve()),str(Path(serial).resolve())],capture_output=True,text=True)
 assert not q.stderr,q.stderr
 j=json.loads(q.stdout);assert (q.returncode==0)==j['ok'];return j
