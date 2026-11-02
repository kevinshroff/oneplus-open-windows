"""One exact-instance restart, with live RAM/owner guards and a fresh resource capture."""
from pathlib import Path
import hashlib,json,uuid
from relay import Relay
W=Path(__file__).resolve().parent;P=W/'private'
b=json.loads((W/'boot-resource.json').read_text());d=json.loads((W/'callback-debugger-observation.json').read_text());f=json.loads((W/'native-cycle.json').read_text())
assert d['phase']=='native_code_matched_deferred_callbacks_armed_target_resumed'and d['session']==b['session']
assert f['phase']=='native_disable_refused_not_disableable_node_unchanged'and f['unchanged_started_node']and f['enable_not_attempted']
R=Relay('native-restart.json',phone_session=b['session']);s=R.s
if 'capture_nonce'not in s:s['capture_nonce']=uuid.uuid4().hex;R.persist()
def op(label,action,**kw):
 r=R.op(label,'phone',action,**kw);assert r['status']=='ok'and r.get('exit_code',0)==0,r;return r
helper=r'X:\OpenG17\payloads\G66-pnp.exe'
assert op('guard-helper-hash','hash',path=helper)['sha256']=='b0764da8c2943af6e684ee29cfc3ef801ce5ad2eae48b4a926972f8afa6b40ab'
before=json.loads(op('fresh-owned-started-RAM-node','exec',argv=[helper,'describe'])['output']);assert before['ok']
node=before['result']['node'];env=before['result']['environment']
assert node['instance']==r'ACPI\OPEN0063\0'and node['service']=='OpenG63'and node['status']&8 and node['problem']==0
assert env==f['disable_response']['result']['environment']
pnputil=r'X:\Windows\System32\pnputil.exe'
assert op('native-system-pnputil-hash','hash',path=pnputil)['sha256']=='f5f02d90f373243a376f90531d28039b5e9d81b27db010a9620a95ad0ccff52d'
s.update(phase='single_exact_instance_restart_requested',before=before,instance=node['instance'],flags=[],reboot_or_force_requested=False);R.persist()
r=R.op('single-targeted-restart','phone','exec',argv=[pnputil,'/restart-device',node['instance']],timeout=180)
s['restart_response']=r;R.persist();assert r['status']=='ok'and r.get('exit_code',0)==0,r
after=json.loads(op('owned-started-after-restart','exec',argv=[helper,'describe'])['output']);s['after']=after;R.persist()
assert after['ok']and after['result']['node']['instance']==node['instance']and after['result']['node']['service']=='OpenG63'and after['result']['node']['problem']==0 and after['result']['node']['status']&8
query=r'X:\OpenG17\payloads\G63-admin.exe';assert op('query-helper-hash','hash',path=query)['sha256']=='ecaca80bff976c4b367c2efda41669fe59ee87b36755ea1ce92aab69b5643757'
r=R.op('single-post-restart-query','phone','exec',argv=[query,'capture',s['capture_nonce']]);v=json.loads(r['output'])if r.get('output')else None;s['capture_response']=v;R.persist()
raw=P/'G66-after-resources.bin';get=R.op('retain-post-restart-608bytes','phone','get',path=r'X:\OpenG17\payloads\G63-assigned-'+s['capture_nonce']+'.bin',save=raw)
assert get['status']=='ok'and raw.stat().st_size==608
assert r['status']=='ok'and r.get('exit_code',0)==0 and v['ok']and v['result']['sha256']==hashlib.sha256(raw.read_bytes()).hexdigest()
health=op('post-restart-health','probe');assert health['detail']['cpus']==8
s.update(phase='native_exact_instance_restart_and_post_restart_resources_retained',session=b['session'],after_resource_sha256=hashlib.sha256(raw.read_bytes()).hexdigest(),callback_trace_audit_pending=True,raw_writes=0,hardware_MMIO_or_IRQ_operation=False)
R.persist();print(json.dumps({k:s[k]for k in ['phase','after_resource_sha256','callback_trace_audit_pending']}),flush=True)
