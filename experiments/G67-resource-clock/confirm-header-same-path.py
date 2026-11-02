"""Confirm the header comparison on one project path, then restore its bytes."""
from pathlib import Path
import hashlib,json,uuid
from relay import Relay
W=Path(__file__).resolve().parent;P=W/'private';R=Relay('same-path-header-comparison.json');s=R.s
old=P/'G67-client-v3.exe';new=P/'G67-client-header61.exe';remote=r'X:\OpenG17\payloads\G67-client-v3.exe';sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(old)=='8e4c392d372c405ecd0c1d738dc2d1b1a2b6757704193bcdeebde441bdc4d94f'
proof=json.loads((W/'native-header-version-probe.json').read_text());assert proof['all_raw_sections_byte_identical']and proof['only_four_header_version_fields_changed']and sha(new)==proof['candidate_sha256']
assert json.loads((W/'loader-trace.json').read_text())['project_IFEO_key_removed']
def op(label,action,**kw):
 r=R.op(label,'phone',action,**kw);assert r['status']=='ok'and r.get('exit_code',0)==0,r;return r
assert op('fresh-original-at-project-path','hash',path=remote)['sha256']==sha(old)
if'nonce'not in s:s['nonce']=uuid.uuid4().hex;R.persist()
assert op('replace-only-owned-project-client','put',file=new,path='G67-client-v3.exe')['sha256']==sha(new)
try:
 assert op('fresh-compatible-header-at-same-path','hash',path=remote)['sha256']==sha(new)
 r=R.op('same-path-compatible-header-query','phone','exec',argv=[remote,'query',s['nonce']]);s['compatible_execution']=r;R.persist()
finally:
 assert op('restore-original-project-client-bytes','put',file=old,path='G67-client-v3.exe')['sha256']==sha(old)
 assert op('fresh-original-restored-at-same-path','hash',path=remote)['sha256']==sha(old);s['original_project_client_bytes_restored']=True;R.persist()
r=R.op('same-path-original-header-query-after-restore','phone','exec',argv=[remote,'query',s['nonce']]);s['restored_original_execution']=r;R.persist()
assert s['compatible_execution']['status']=='error'and s['compatible_execution']['exit_code']==1
assert json.loads(s['compatible_execution']['output'])=={'ok':False,'stage':'DSDT-length','error':576,'interfaces_queried':0,'file_opens':0,'ioctls':0}
assert r['status']=='error'and r['exit_code']==0xc000007b and not r['output']
s.update(phase='same_path_native_header_dependency_confirmed_and_original_bytes_restored',original_sha256=sha(old),compatible_sha256=sha(new),all_raw_sections_byte_identical=True,header_changed_offsets=proof['changed_file_offsets'],precise_internal_loader_predicate_reconstructed=False,native_clock_trial_requested=False);R.persist();print(json.dumps({k:s[k]for k in ['phase','original_project_client_bytes_restored','precise_internal_loader_predicate_reconstructed']}))
