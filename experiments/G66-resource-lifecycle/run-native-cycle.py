"""One owned-device disable/enable cycle; never replay either call after timeout."""
from pathlib import Path
import hashlib,json,uuid
from relay import Relay
W=Path(__file__).resolve().parent;P=W/'private'
b=json.loads((W/'boot-resource.json').read_text());d=json.loads((W/'callback-debugger-observation.json').read_text());q=json.loads((W/'pnp-preflight.json').read_text())
assert d['phase']=='native_code_matched_deferred_callbacks_armed_target_resumed'and d['session']==b['session']
assert d['native_code_sha256']=='1a7168de99cbd9875e6c2243d3ba265eecf4b26c779d5d3e47309f2d7fbe3575'
assert q['native_CM_mutation_calls']==0 and q['before']==q['after']
R=Relay('native-cycle.json',phone_session=b['session']);s=R.s
for name in ['nonce','after_capture_nonce']:
 if name not in s:s[name]=uuid.uuid4().hex;R.persist()
def op(label,action,**kw):
 r=R.op(label,'phone',action,**kw);assert r['status']=='ok'and r.get('exit_code',0)==0,r;return r
tool=r'X:\OpenG17\payloads\G66-pnp.exe'
assert op('qualified-helper-hash','hash',path=tool)['sha256']==q['binary_sha256']
for mode in ['disable','enable']:
 s['phase']='single_native_'+mode+'_requested';R.persist()
 r=R.op('single-'+mode,'phone','exec',argv=[tool,mode,s['nonce']],timeout=180)
 v=json.loads(r['output'])if r.get('output')else None;s[mode+'_response']=v;R.persist()
 assert r['status']=='ok'and r.get('exit_code',0)==0 and v['ok'],r
 out=v['result'];assert out['mode']==mode and out['nonce']==s['nonce']and out['CR']==0 and out['verified']and out['api_reported_success']
 assert out['flags']==(4 if mode=='disable'else 0)and out['before']['instance']==out['after']['instance']==r'ACPI\OPEN0063\0'
 if mode=='disable':assert out['after']['problem']==22 and not(out['after']['status']&8)
 else:assert out['after']['problem']==0 and out['after']['status']&8
 remote=r'X:\OpenG17\payloads\G66-'+s['nonce']+'-'+mode+'-result.json';local=P/(mode+'-result.json')
 op('retain-'+mode+'-result','get',path=remote,save=local);assert json.loads(local.read_text())==out
 s[mode+'_verified']=True;R.persist()
describe=json.loads(op('owned-started-after-cycle','exec',argv=[tool,'describe'])['output']);assert describe['ok']and describe['result']['node']['problem']==0 and describe['result']['node']['status']&8
query=r'X:\OpenG17\payloads\G63-admin.exe'
assert op('query-helper-hash','hash',path=query)['sha256']=='ecaca80bff976c4b367c2efda41669fe59ee87b36755ea1ce92aab69b5643757'
r=R.op('single-post-cycle-resource-capture','phone','exec',argv=[query,'capture',s['after_capture_nonce']]);v=json.loads(r['output'])if r.get('output')else None;s['capture_response']=v;R.persist()
remote=r'X:\OpenG17\payloads\G63-assigned-'+s['after_capture_nonce']+'.bin';raw=P/'G66-after-resources.bin'
g=R.op('retain-post-cycle-608bytes','phone','get',path=remote,save=raw)
assert g['status']=='ok'and raw.stat().st_size==608
assert r['status']=='ok'and r.get('exit_code',0)==0 and v['ok']and v['result']['sha256']==hashlib.sha256(raw.read_bytes()).hexdigest()
health=op('post-cycle-health','probe');assert health['detail']['cpus']==8
s.update(phase='native_owned_devnode_disable_enable_and_post_cycle_resources_retained',session=b['session'],after_resource_sha256=hashlib.sha256(raw.read_bytes()).hexdigest(),callback_trace_audit_pending=True,raw_writes=0,hardware_MMIO_or_IRQ_operation=False)
R.persist();print(json.dumps({k:s[k]for k in ['phase','after_resource_sha256','callback_trace_audit_pending']}),flush=True)
