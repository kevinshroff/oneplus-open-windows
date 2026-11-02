"""Remove only the five owned probes and resume; never replay the UI action."""
from pathlib import Path
import hashlib,json
from relay import Relay
W=Path(__file__).resolve().parent;P=W/'private';a=json.loads((W/'native-lifecycle-audit.json').read_text());b=json.loads((W/'boot-resource.json').read_text())
assert a['passed']and a['native_restart_and_resource_lifecycle_qualified']
R=Relay('debugger-cleanup.json',phone_session=b['session']);s=R.s
def op(label,action,**kw):
 r=R.op(label,'host',action,**kw);assert r['status']=='ok'and r.get('exit_code',0)==0,r;return r
for p in [P/'G66-cleanup.txt',W/'cleanup-debugger-ui.ps1']:
 assert op('stage-'+p.name,'put',file=p,path=p.name)['sha256']==hashlib.sha256(p.read_bytes()).hexdigest()
r=op('single-owned-probe-cleanup','exec',argv=['powershell.exe','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',r'C:\Users\PUBLIC_USER\Downloads\Open-G17\payloads\cleanup-debugger-ui.ps1'])
s.update(phase='owned_probe_cleanup_submitted_once',ui_action=json.loads(r['output']));R.persist();print(s['phase'],flush=True)
