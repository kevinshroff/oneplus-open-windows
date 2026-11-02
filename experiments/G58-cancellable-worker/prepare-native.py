"""Stage fixed helpers; verify unchanged baseline and a finite owned receiver."""
from pathlib import Path
import argparse,hashlib,json
from relay import Relay
W=Path(__file__).resolve().parent;p=argparse.ArgumentParser();p.add_argument('--phase',choices=['helpers','receiver'],required=True);a=p.parse_args();R=Relay('native-preparation.json');s=R.s;base=r'X:\OpenG17\payloads';sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def op(label,action,**kw):
 r=R.op(label,'phone',action,**kw);assert r['status']=='ok'and r.get('exit_code',0)==0,r;return r
def run(label,args):
 r=op(label,'exec',argv=args);v=json.loads(r['output']);assert v['ok'],v;return v['result']
if a.phase=='helpers':
 for name,folder in [('admin','admin-02'),('child','child-01'),('cleanup','cleanup-01'),('receiver','receiver-01')]:
  b=W/'private'/folder/('g58-'+name+'-arm64.exe');m=json.loads((b.parent/'build.json').read_text());assert m['binary_sha256']==sha(b)
  for n,h in m.get('source_files_sha256',{m['source']:m['source_sha256']}).items():assert sha(W/n)==h
  remote=base+'\\G58-'+name+'.exe';assert op('put-'+name,'put',file=b,path=remote)['sha256']==sha(b);assert op('hash-'+name,'hash',path=remote)['sha256']==sha(b)
 s['baseline']=run('baseline',[base+r'\G58-admin.exe','inventory']);R.persist();s['audit_before']=run('audit-before',[base+r'\G58-cleanup.exe','audit']);R.persist()
 v=s['audit_before'];assert v['owned_roots']==0 and v['source_interfaces']==[]and not v['source_service']['present']and not v['inbox_include']['present']and v['processors']==8 and v['inventory']['SM_DIGITIZER']==0
 s['phase']='helpers_verified_original_input_baseline_saved';R.persist()
elif a.phase=='receiver':
 assert s['phase']=='helpers_verified_original_input_baseline_saved'
 if 'receiver_token'not in s:
  import secrets
  s['receiver_token']=secrets.token_hex(16);R.persist()
 token=s['receiver_token'];s['selftest']=run('receiver-selftest',[base+r'\G58-receiver.exe','selftest',base,token]);R.persist()
 for name in ['ready','qualification','wrong-pid','done','events']:
  suffix='.jsonl'if name=='events'else'.json';f=W/'private'/('receiver-selftest-'+name+suffix)
  op('get-selftest-'+name,'get',path=base+'\\G58-receiver-'+token+'-'+name+suffix,save=f if not f.exists()else None)
 q=json.loads((W/'private/receiver-selftest-qualification.json').read_text());d=json.loads((W/'private/receiver-selftest-done.json').read_text());assert q['owned_foreground_verified']and q['DPI_aware']and q['wrong_PID_refused']and d['window_closed']and d['events']==d['dropped']==d['driver_requests_submitted']==0
 s['phase']='finite_owned_foreground_DPI_receiver_selftest_passed_no_driver_IO';R.persist()
print(json.dumps({'phase':s['phase'],'jobs':len(s['jobs'])}))
