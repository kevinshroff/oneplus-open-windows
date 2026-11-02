"""Recheck already staged unchanged helpers and original stack, before new root."""
from pathlib import Path
import hashlib,json,subprocess,sys
from relay import Relay
W=Path(__file__).resolve().parent;B=W.parent/'contact-cancel-G60';K=W.parent/'stream-G59';R=Relay('native-preparation.json');base=r'X:\OpenG17\payloads';sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
subprocess.run([sys.executable,str(W/'preflight.py')],check=True,capture_output=True,text=True)
def op(label,action,**kw):
 r=R.op(label,'phone',action,**kw);assert r['status']=='ok'and not r.get('exit_code',0),r;return r
def native(label,argv):
 v=json.loads(op(label,'exec',argv=argv)['output']);assert v['ok'],v;return v['result']
remote=base+r'\G60-idle-admin-v2.exe';caller_sha=json.loads((B/'private/idle-admin-02/build.json').read_text())['binary_sha256']
for label,path in [('caller',remote),('guarded-caller',base+r'\G60-idle-stop-capture\G59-admin.exe')]:assert op('hash-'+label,'hash',path=path)['sha256']==caller_sha
for name in ['receiver','child','cleanup']:
 m=json.loads((K/'private'/(name+'-01')/'build.json').read_text());assert op('hash-'+name,'hash',path=base+'\\G59-'+name+'.exe')['sha256']==m['binary_sha256']
R.s['baseline']=native('fresh-baseline',[remote,'inventory']);R.s['audit_before']=native('fresh-audit-before',[base+r'\G59-cleanup.exe','audit']);R.persist()
v=R.s['audit_before'];prior=json.loads((B/'native-qualification-idle-stop-v2.json').read_text())['audit_after']['inventory'];assert v['owned_roots']==0 and v['source_interfaces']==[]and not v['source_service']['present']and not v['inbox_include']['present']and v['processors']==8 and v['inventory']['SM_DIGITIZER']==0
assert R.s['baseline']['files']==prior['files']and R.s['baseline']['services']==prior['services']and R.s['baseline']['DSDT_sha256']==prior['DSDT_sha256']
R.s['reused_G59_receiver_selftest_sha256']=sha(K/'private/receiver-selftest-qualification.json');R.s['no_new_helper_build_or_staging']=True;R.s['phase']='unchanged_helpers_and_original_baseline_verified';R.persist();print(json.dumps({'phase':R.s['phase']}))
