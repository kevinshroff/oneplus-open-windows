"""One recorded debugger replacement; observation deadlines never relaunch it."""
from pathlib import Path
import hashlib,json
from relay import Relay
W=Path(__file__).resolve().parent;P=W/'private';b=json.loads((W/'boot-resource.json').read_text());q=json.loads((W/'pnp-preflight.json').read_text())
assert b['root']['x_is_ramdisk']and q['phase']=='native_helper_refusals_and_unchanged_owned_started_node_verified'
R=Relay('callback-debugger-launch.json',phone_session=b['session']);s=R.s
def op(label,action,**kw):
 r=R.op(label,'host',action,**kw);assert r['status']=='ok'and r.get('exit_code',0)==0,r;return r
for p in [P/'G66-first-attach.txt',W/'start-callback-debugger.ps1']:
 assert op('stage-'+p.name,'put',file=p,path=p.name)['sha256']==hashlib.sha256(p.read_bytes()).hexdigest()
base='C:\\Users\\PUBLIC_USER\\Downloads\\Open-G17\\payloads\\'
r=op('single-launch','exec',argv=['powershell.exe','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',base+'start-callback-debugger.ps1'])
v=json.loads(r['output']);assert v['phase']=='launch_accepted'and v['auto_resume']and not v['firewall_modified']
s.update(phase='single_callback_debugger_launch_acknowledged',launch=v);R.persist();print(s['phase'],flush=True)
