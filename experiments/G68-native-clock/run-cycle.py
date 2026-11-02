"""One finite native cycle, only after the independently audited fresh query."""
from pathlib import Path
import hashlib,json,subprocess,sys
from relay import Relay
W=Path(__file__).resolve().parent;P=W/'private'
b=json.loads((W/'boot-resource.json').read_text());a=json.loads((W/'native-before-audit.json').read_text())
assert a['passed']and a['hardware_register_operations']==0
assert hashlib.sha256((P/'G67-native-before.bin').read_bytes()).hexdigest()==a['report']['sha256']
R=Relay('native-clock.json',phone_session=b['session']);s=R.s
assert s['bind_result']['result']['result']['bound']
client=r'X:\OpenG17\payloads\G67-client.exe'
r=R.op('pre-cycle-client-hash','phone','hash',path=client);assert r['status']=='ok'and r['sha256']=='1560529b8c0d46eabb54825a4cedaf07c743746f8df08b211a0e43c963116a87'
s['phase']='single_native_finite_clock_cycle_requested';R.persist()
r=R.op('single-native-clock-cycle','phone','exec',argv=[client,'cycle',s['cycle_nonce']])
s['cycle_result']=json.loads(r['output'])if r.get('output')else None;R.persist()
# The native client saves the raw result before declaring cycle success.
remote=r'X:\OpenG17\payloads\G67-clock-'+s['cycle_nonce']+'.bin'
g=R.op('retain-cycle-packet','phone','get',path=remote,save=P/'G67-native-cycle.bin')
assert g['status']=='ok'and(P/'G67-native-cycle.bin').stat().st_size==1872
assert r['status']=='error'and r.get('exit_code')==1 and s['cycle_result']=={'ok':False,'captured':True,'mode':'cycle','nonce':s['cycle_nonce'],'bytes':1872,'code':5,'restore_error':0,'restored':1},r
subprocess.run([sys.executable,str(W/'audit-native.py'),'cycle'],check=True)
s.update(phase='native_root_status_policy_refusal_exact_restore_and_core_replay_verified',native_cycle_qualified=False,cycle_was_not_repeated=True);R.persist()
print(s['phase'],flush=True)
