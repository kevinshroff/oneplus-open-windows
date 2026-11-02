"""Read the cached result once after the guarded refusal; no hardware retry."""
from pathlib import Path
import hashlib,json,uuid
from relay import Relay
W=Path(__file__).resolve().parent;P=W/'private'
b=json.loads((W/'boot-resource.json').read_text());a=json.loads((W/'native-cycle-audit.json').read_text())
assert a['passed']and a['policy_refusal_reproduced_from_native_reads']
R=Relay('native-clock.json',phone_session=b['session']);s=R.s
if'post_query_nonce'not in s:s['post_query_nonce']=uuid.uuid4().hex;R.persist()
r=R.op('single-cached-query-after-refusal','phone','exec',argv=[r'X:\OpenG17\payloads\G67-client.exe','query',s['post_query_nonce']])
assert r['status']=='ok'and r.get('exit_code',0)==0
v=json.loads(r['output']);assert v['ok']and v['captured']and v['code']==5 and v['restore_error']==0 and v['restored']==1
remote=r'X:\OpenG17\payloads\G67-clock-'+s['post_query_nonce']+'.bin'
g=R.op('retain-cached-post-refusal-packet','phone','get',path=remote,save=P/'G67-native-post-query.bin')
assert g['status']=='ok'and(P/'G67-native-post-query.bin').read_bytes()==(P/'G67-native-cycle.bin').read_bytes()
h=R.op('post-refusal-health','phone','probe');assert h['status']=='ok'and h['detail']['arch']=='arm64'and h['detail']['cpus']==8
s.update(post_refusal_cached_query_byte_identical=True,post_refusal_query_result=v,post_refusal_packet_sha256=hashlib.sha256((P/'G67-native-post-query.bin').read_bytes()).hexdigest(),phase='one_cycle_guard_refusal_restored_cached_state_stable_8CPU_control_healthy');R.persist()
print(json.dumps({'post_refusal_cached_query_byte_identical':True,'native_clock_cycle_attempts':1,'independent_clock_word_readback_baseline_restored':True,'control_8CPUs_healthy':True}),flush=True)
