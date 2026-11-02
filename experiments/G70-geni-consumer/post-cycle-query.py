"""Verify one cached post-cycle capture is identical; no hardware cycle retry."""
from pathlib import Path
import hashlib,json,uuid
from relay import Relay
W=Path(__file__).resolve().parent;P=W/'private'
b=json.loads((W/'boot-resource.json').read_text());a=json.loads((W/'native-cycle-audit.json').read_text())
assert a['passed']and a['native_finite_clock_cycle_and_restoration_qualified']
R=Relay('native-clock.json',phone_session=b['session']);s=R.s
if'post_query_nonce'not in s:s['post_query_nonce']=uuid.uuid4().hex;R.persist()
r=R.op('single-cached-query-after-cycle','phone','exec',argv=[r'X:\OpenG17\payloads\G70-client.exe','query',s['post_query_nonce']])
assert r['status']=='ok'and r.get('exit_code',0)==0
v=json.loads(r['output']);assert v['ok']and v['captured']and v['code']==v['restore_error']==0 and v['restored']==1
g=R.op('retain-cached-post-cycle-packet','phone','get',path=r'X:\OpenG17\payloads\G70-consumer-'+s['post_query_nonce']+'.bin',save=P/'G70-native-post-query.bin')
assert g['status']=='ok'and(P/'G70-native-post-query.bin').read_bytes()==(P/'G70-native-cycle.bin').read_bytes()
h=R.op('post-cycle-health','phone','probe');assert h['status']=='ok'and h['detail']['arch']=='arm64'and h['detail']['cpus']==8
s.update(post_cycle_cached_query_byte_identical=True,post_cycle_query_result=v,post_cycle_packet_sha256=hashlib.sha256((P/'G70-native-post-query.bin').read_bytes()).hexdigest(),phase='native_clock_cycle_replayed_restored_cached_state_stable_and_8CPU_control_healthy');R.persist()
print(json.dumps({'post_cycle_cached_query_byte_identical':True,'native_clock_cycle_attempts':1,'all_six_clock_words_restored':True,'control_8CPUs_healthy':True}),flush=True)
