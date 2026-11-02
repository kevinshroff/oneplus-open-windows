"""Keep the GUI inside one finite G17 command; no HID/device submission."""
from pathlib import Path
import hashlib,json,uuid
from relay import Relay
W=Path(__file__).resolve().parent;R=Relay('receiver-coordinator-v5-native.json');s=R.s;sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
old=json.loads((W/'receiver-native.json').read_text());assert old['recorded_worker_terminal'].get('process_absent')or old['recorded_worker_terminal'].get('process_terminal')
binary=W/'private/receiver-05/g55-receiver-arm64.exe';build=json.loads((W/'private/receiver-05/build.json').read_text());assert build['binary_sha256']==sha(binary)and build['source_sha256']==sha(W/'g55_receiver.go')
base=r'X:\OpenG17\payloads';remote=base+r'\G55-receiver-v5.exe';local=W/'private/receiver-coordinator-02';local.mkdir(exist_ok=True)
def op(label,action,allow_failure=False,**kw):
 r=R.op(label,'phone',action,**kw)
 if not allow_failure:assert r['status']=='ok'and r.get('exit_code',0)==0,r
 return r
q=op('probe','probe');assert q['detail']['cpus']==8 and q['detail']['arch']=='arm64'
assert op('put','put',file=binary,path=remote)['sha256']==sha(binary)
assert op('hash','hash',path=remote)['sha256']==sha(binary)
if 'token'not in s:s.update(token=uuid.uuid4().hex,binary_sha256=sha(binary),mode='selftest',max_window_seconds=5,driver_requests=0);R.persist()
r=op('single-finite-window-job','exec',argv=[remote,'selftest',base,s['token']],timeout=30,allow_failure=True);s['window_result']=r;R.persist();q=json.loads(r['output']);assert r['status']=='ok'and r['exit_code']==0 and q['ok'],r
for label,suffix in [('ready','ready.json'),('qualification','qualification.json'),('events','events.jsonl'),('done','done.json')]:
 p=local/suffix;r=op(label,'get',path=base+'\\G55-receiver-'+s['token']+'-'+suffix,save=p if not p.exists()else None);assert sha(p)==r['sha256']
ready=json.loads((local/'ready.json').read_text());qualification=json.loads((local/'qualification.json').read_text());done=json.loads((local/'done.json').read_text())
assert ready['Token']==done['token']==s['token']and ready['Foreground']and ready['DPIAware']and ready['Width']==2440 and ready['Height']==2268
assert qualification['owned_foreground_verified']and qualification['DPI_aware']and qualification['wrong_PID_refused']=='owned receiver is not the foreground window'
assert done['window_closed']and done['driver_requests_submitted']==0 and 5000<=done['tick']-ready['Tick']<15000 and done['dropped']==0
r=op('observe-completed-window-process','exec',argv=[base+r'\G55-process.exe',str(ready['PID'])]);v=json.loads(r['output']);assert v.get('process_absent')or v.get('process_terminal')
r=op('probe-end','probe');assert r['detail']['cpus']==8 and r['detail']['arch']=='arm64'
s.update(phase='owned_fullscreen_foreground_guard_wrong_PID_refusal_finite_closure_passed',ready=ready,qualification=qualification,done=done,worker_terminal=v);R.persist();print(json.dumps({'phase':s['phase'],'jobs':len(s['jobs']),'duration_ticks_ms':done['tick']-ready['Tick'],'driver_requests':0}))
