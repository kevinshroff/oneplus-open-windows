"""Verify the real helper policy rejects prior native idle/startup cancellation."""
from pathlib import Path
import argparse,hashlib,json,subprocess
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--previous-cancel',type=Path);p.add_argument('--previous-idle',type=Path);a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True);W=Path(__file__).resolve().parent
for n in ['g59_cancel.go']: (a.output/n).write_bytes((W/n).read_bytes())
(a.output/'main.go').write_text(r'''package main
import("encoding/json";"os";"fmt")
func must(v bool){if !v{panic("policy expectation failed")}}
func copyMap(s map[string]any)map[string]any{r:=map[string]any{};for k,v:=range s{r[k]=v};return r}
func native(path string,key string)map[string]any{b,e:=os.ReadFile(path);if e!=nil{panic(e)};var d map[string]any;must(json.Unmarshal(b,&d)==nil);v:=d[key].(map[string]any);r:=map[string]any{};for k,x:=range v{if n,ok:=x.(float64);ok&&n>=0&&n<=4294967295{r[k]=uint32(n)}else{r[k]=x}};return r}
func main(){cases:=0
 s:=map[string]any{"state":uint32(2),"phase":uint32(9),"starts":uint32(1),"hardware_calls":uint32(1),"result_ready":uint32(0),"outcome":uint32(0),"stop_reason":uint32(0),"poll_cycles":uint32(1000)}
 for c:=uint32(0);c<=3000;c++{v:=copyMap(s);v["poll_cycles"]=c;must(cancelEligible(v)==(c>=1000&&c<2500));cases++}
 for k,v:=range s{for _,bad:=range []any{nil,"1",float64(1),uint32(0xffffffff)}{x:=copyMap(s);x[k]=bad;must(!cancelEligible(x));cases++};x:=copyMap(s);delete(x,k);must(!cancelEligible(x));cases++;_ = v}
 for _,k:=range []string{"state","phase","starts","hardware_calls","result_ready","outcome","stop_reason"}{x:=copyMap(s);x[k]=s[k].(uint32)^1;must(!cancelEligible(x));cases++}
 r:=map[string]any{"accepted_mask":uint32(0),"stop_attempts":uint32(1),"stop_accepted":uint32(1),"live_complete":uint32(0),"live_error":uint32(6),"reports_submitted":uint32(401),"reports_accepted":uint32(401),"accepted_generation":uint32(401)};must(activeRelease(r));cases++
 for k,v:=range r{for _,bad:=range []any{nil,"1",float64(1),v.(uint32)^1}{x:=copyMap(r);x[k]=bad;must(!activeRelease(x));cases++};x:=copyMap(r);delete(x,k);must(!activeRelease(x));cases++}
 for _,n:=range []uint32{0,1}{x:=copyMap(r);x["reports_submitted"]=n;x["reports_accepted"]=n;x["accepted_generation"]=n;must(!activeRelease(x));cases++}
 for _,path:=range os.Args[1:]{must(!cancelEligible(native(path,"session_after"))&&!activeRelease(native(path,"source_after")));cases+=2}
 idle:=map[string]any{"accepted_mask":uint32(0),"stop_attempts":uint32(1),"stop_accepted":uint32(0),"live_complete":uint32(0),"live_error":uint32(6),"reports_submitted":uint32(0),"reports_accepted":uint32(0),"accepted_generation":uint32(0)}
 must(cancelRelease(idle,"idle")&&!cancelRelease(idle,"active")&&cancelRelease(r,"active")&&!cancelRelease(r,"idle")&&!cancelRelease(r,"unknown"));cases+=5
 for k,v:=range idle{for _,bad:=range []any{nil,"1",float64(1),v.(uint32)^1}{x:=copyMap(idle);x[k]=bad;must(!idleRelease(x));cases++}}
 fmt.Printf("{\"passed\":true,\"cases\":%d,\"prior_native_startup_cancel_and_sustained_idle_cannot_qualify_active_cancel\":true,\"positive_active_release_is_modeled_only\":true,\"native_operations\":0}\n",cases)
}
''')
q=subprocess.run(['go','run',str(a.output/'g59_cancel.go'),str(a.output/'main.go'),str(a.previous_cancel or W.parent/'worker-G58/cancel-native-stop.json'),str(a.previous_idle or W.parent/'stream-G59/live-native-idle.json')],capture_output=True,text=True);assert not q.returncode and not q.stderr,(q.stdout,q.stderr);v=json.loads(q.stdout);v['policy_source_sha256']=hashlib.sha256((W/'g59_cancel.go').read_bytes()).hexdigest();(a.output/'tests.json').write_text(json.dumps(v,indent=2)+'\n');print(json.dumps(v))
