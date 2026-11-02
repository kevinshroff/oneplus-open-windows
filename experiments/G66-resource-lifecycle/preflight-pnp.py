"""Stage the reproducible helper and qualify native refusal without changing a device."""
from pathlib import Path
import hashlib,json,uuid
from relay import Relay
W=Path(__file__).resolve().parent;P=W/'private';b=json.loads((W/'boot-resource.json').read_text());n=json.loads((W/'native-resource-recorder.json').read_text())
assert b['root']['x_is_ramdisk']and b['all_six_GPTs_byte_identical_to_baseline']and n['native_resource_handoff_qualified']
a=json.loads((P/'pnp-build-01/build.json').read_text());a2=json.loads((P/'pnp-rebuild-01/build.json').read_text());assert a['binary_sha256']==a2['binary_sha256']and a['source_sha256']==a2['source_sha256']and a['guard_cases']==63
R=Relay('pnp-preflight.json',phone_session=b['session']);s=R.s
if 'nonce'not in s:s['nonce']=uuid.uuid4().hex;R.persist()
def op(label,action,**kw):
 r=R.op(label,'phone',action,**kw);assert r['status']=='ok'and r.get('exit_code',0)==0,r;return r
exe=P/'pnp-build-01/g66-pnp-arm64.exe';assert hashlib.sha256(exe.read_bytes()).hexdigest()==a['binary_sha256']
remote=r'X:\OpenG17\payloads\G66-pnp.exe'
assert op('put-helper','put',file=exe,path='G66-pnp.exe')['sha256']==a['binary_sha256']
assert op('native-helper-hash','hash',path=remote)['sha256']==a['binary_sha256']
before=json.loads(op('owned-started-node-before','exec',argv=[remote,'describe'])['output']);assert before['ok']and before['result']['node']['problem']==0 and before['result']['node']['status']&8
for label,mode,nonce in [('bad-nonce','disable','INVALID'),('unsupported-mode','remove',s['nonce']),('missing-disable-receipt','enable',s['nonce'])]:
 r=R.op(label,'phone','exec',argv=[remote,mode,nonce]);assert r['status']=='error'and r['exit_code']==1,r
 v=json.loads(r['output']);assert not v['ok'];s.setdefault('native_refusals',{})[label]=v;R.persist()
after=json.loads(op('owned-started-node-after','exec',argv=[remote,'describe'])['output']);assert after==before
s.update(phase='native_helper_refusals_and_unchanged_owned_started_node_verified',binary_sha256=a['binary_sha256'],before=before,after=after,native_CM_mutation_calls=0)
R.persist();print(json.dumps({k:s[k]for k in ['phase','binary_sha256','native_CM_mutation_calls']}),flush=True)
