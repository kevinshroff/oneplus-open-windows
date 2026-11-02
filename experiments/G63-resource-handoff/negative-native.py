"""Prove the actual ARM64 helper refuses normal G17 before any pilot operation."""
from pathlib import Path
import hashlib,json,uuid
from relay import Relay
W=Path(__file__).resolve().parent;R=Relay('normal-G17-refusal.json');s=R.s;J=lambda p:json.loads(p.read_text());sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();assert J(W.parent/'resources-G62/resource-audit.json')['passed'];m=J(W/'private/admin-01/build.json');p=W/'private/admin-01/g63-admin-arm64.exe';assert sha(p)==m['binary_sha256'];remote=r'X:\OpenG17\payloads\G63-admin.exe';cleanup=r'X:\OpenG17\payloads\G59-cleanup.exe'
if'token'not in s:s['token']=uuid.uuid4().hex;R.persist()
def op(label,action,**kw):
 r=R.op(label,'phone',action,**kw);assert r['status']=='ok'and r.get('exit_code',0)==0,r;return r
r=op('audit-before','exec',argv=[cleanup,'audit']);s['audit_before']=json.loads(r['output'])['result'];R.persist();assert s['audit_before']==J(W.parent/'resources-G62/native-snapshot-v2.json')['audit_after']
assert op('put-helper','put',file=p,path=remote)['sha256']==m['binary_sha256'];assert op('hash-helper','hash',path=remote)['sha256']==m['binary_sha256']
r=R.op('single-negative-invocation','phone','exec',argv=[remote,'capture',s['token']]);assert r['status']=='error'and r['exit_code']==1,r;v=json.loads(r['output']);assert v['ok']==False and'G63 trial DSDT length576 differs'in v['error']and v['result']is None
r=R.op('evidence-file-absent','phone','hash',path=r'X:\OpenG17\payloads\G63-assigned-'+s['token']+'.bin');assert r['status']=='error'and'cannot find'in r.get('error',r.get('output','')).lower(),r
r=op('audit-after','exec',argv=[cleanup,'audit']);s['audit_after']=json.loads(r['output'])['result'];assert s['audit_after']==s['audit_before'];q=op('probe-after','probe');assert q['detail']['cpus']==8 and q['detail']['arch']=='arm64';s.update(phase='native_ARM64_helper_refuses_original_G17_before_pilot_interface_or_file_operation',native_resource_handoff_qualified=False,driver_loaded=False,certificate_store_changed=False,normal_G17_software_stack_unchanged=True);R.persist();print(json.dumps({'phase':s['phase'],'normal_G17_same_session':True}))
