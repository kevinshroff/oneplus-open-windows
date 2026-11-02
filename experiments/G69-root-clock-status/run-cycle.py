"""One finite native cycle, only after the independently audited fresh query."""
from pathlib import Path
import hashlib,json,subprocess,sys
from relay import Relay
W=Path(__file__).resolve().parent;P=W/'private'
b=json.loads((W/'boot-resource.json').read_text());a=json.loads((W/'native-before-audit.json').read_text())
assert a['passed']and a['hardware_register_operations']==0
assert hashlib.sha256((P/'G69-native-before.bin').read_bytes()).hexdigest()==a['report']['sha256']
R=Relay('native-clock.json',phone_session=b['session']);s=R.s
assert s['bind_result']['result']['result']['bound']
client=r'X:\OpenG17\payloads\G69-client.exe'
r=R.op('pre-cycle-client-hash','phone','hash',path=client);assert r['status']=='ok'and r['sha256']=='73c18aaa1367a6bdf8400f0743ed3beb158928a9c7de1c1b9aee33371a92dc64'
s['phase']='single_native_finite_clock_cycle_requested';R.persist()
r=R.op('single-native-clock-cycle','phone','exec',argv=[client,'cycle',s['cycle_nonce']])
s['cycle_result']=json.loads(r['output'])if r.get('output')else None;R.persist()
# The native client saves the raw result before declaring cycle success.
remote=r'X:\OpenG17\payloads\G69-clock-'+s['cycle_nonce']+'.bin'
g=R.op('retain-cycle-packet','phone','get',path=remote,save=P/'G69-native-cycle.bin')
assert g['status']=='ok'and(P/'G69-native-cycle.bin').stat().st_size==1872
assert r['status']=='ok'and r.get('exit_code',0)==0 and s['cycle_result']['ok'],r
subprocess.run([sys.executable,str(W/'audit-native.py'),'cycle'],check=True)
s.update(phase='native_corrected_root_status_clock_cycle_exact_restore_and_core_replay_verified',native_cycle_qualified=True,cycle_was_not_repeated=True);R.persist()
print(s['phase'],flush=True)
