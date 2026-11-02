"""Stage only the idle-profile caller; reuse exact qualified G59 receiver/helpers."""
from pathlib import Path
import hashlib,json,subprocess,sys
from relay import Relay
W=Path(__file__).resolve().parent;B=W.parent/'stream-G59';R=Relay('native-preparation-v2.json');base=r'X:\OpenG17\payloads';sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
subprocess.run([sys.executable,str(W/'preflight.py')],check=True,capture_output=True,text=True)
def op(label,action,**kw):
 r=R.op(label,'phone',action,**kw);assert r['status']=='ok'and not r.get('exit_code',0),r;return r
def native(label,argv):
 v=json.loads(op(label,'exec',argv=argv)['output']);assert v['ok'],v;return v['result']
p=W/'private/idle-admin-02/g60-admin-idle-arm64.exe';remote=base+r'\G60-idle-admin-v2.exe';assert op('put-idle-caller','put',file=p,path=remote)['sha256']==sha(p);assert op('hash-idle-caller','hash',path=remote)['sha256']==sha(p)
target=base+r'\G60-idle-stop-capture\G59-admin.exe';assert op('put-guarded-caller','put',file=p,path=target)['sha256']==sha(p);assert op('hash-guarded-caller','hash',path=target)['sha256']==sha(p)
for name in ['receiver','child','cleanup']:
 m=json.loads((B/'private'/(name+'-01')/'build.json').read_text());assert op('hash-G59-'+name,'hash',path=base+'\\G59-'+name+'.exe')['sha256']==m['binary_sha256']
R.s['baseline']=native('fresh-baseline',[remote,'inventory']);R.s['audit_before']=native('fresh-audit-before',[base+r'\G59-cleanup.exe','audit']);R.persist()
v=R.s['audit_before'];prior=json.loads((B/'native-qualification-idle.json').read_text())['audit_after']['inventory'];assert v['owned_roots']==0 and v['source_interfaces']==[]and not v['source_service']['present']and not v['inbox_include']['present']and v['processors']==8 and v['inventory']['SM_DIGITIZER']==0
assert R.s['baseline']['files']==prior['files']and R.s['baseline']['services']==prior['services']and R.s['baseline']['DSDT_sha256']==prior['DSDT_sha256']
R.s['reused_receiver_selftest_from_G59']={'qualification_sha256':sha(B/'private/receiver-selftest-qualification.json'),'receiver_binary_sha256':json.loads((B/'private/receiver-01/build.json').read_text())['binary_sha256'],'new_G60_selftest_invocation':False};R.s['phase']='reused_receiver_selftest_new_idle_helper_and_baseline_verified';R.persist();print(json.dumps({'phase':R.s['phase']}))
