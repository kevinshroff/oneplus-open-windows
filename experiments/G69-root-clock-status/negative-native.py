"""Exercise only native refusal on original G17; never installs or opens a driver."""
from pathlib import Path
import hashlib,json,uuid
from relay import Relay
W=Path(__file__).resolve().parent;P=W/'private';v=json.loads((W/'client-verification.json').read_text());assert v['passed']and v['bytes']<=49152
R=Relay('normal-G17-refusal.json');s=R.s
def op(label,action,**kw):
 r=R.op(label,'phone',action,**kw);assert r['status']=='ok'and r.get('exit_code',0)==0,r;return r
health=op('before-health','probe');assert health['detail']['arch']=='arm64'and health['detail']['cpus']==8
audit=r'X:\OpenG17\payloads\G59-cleanup.exe'
before=json.loads(op('before-original-stack','exec',argv=[audit,'audit'])['output'])['result'];assert before==json.loads((W.parent/'resources-G63/normal-G17-refusal.json').read_text())['audit_after'];s['audit_before']=before;R.persist()
exe=P/'G69-client.exe';assert hashlib.sha256(exe.read_bytes()).hexdigest()==v['binary_sha256']
assert op('stage-small-project-client','put',file=exe,path='G69-client.exe')['sha256']==v['binary_sha256']
remote=r'X:\OpenG17\payloads\G69-client.exe';assert op('native-client-hash','hash',path=remote)['sha256']==v['binary_sha256']
if'nonce'not in s:s['nonce']=uuid.uuid4().hex;R.persist()
observed={}
for mode in ['query','cycle']:
 r=R.op('refuse-'+mode,'phone','exec',argv=[remote,mode,s['nonce']]);assert r['status']=='error'and r['exit_code']==1,r
 x=json.loads(r['output']);assert x=={'ok':False,'stage':'DSDT-length','error':576,'interfaces_queried':0,'file_opens':0,'ioctls':0},x;observed[mode]=x;s['native_refusals']=observed;R.persist()
r=R.op('refuse-invalid-arguments','phone','exec',argv=[remote,'cycle','badnonce']);assert r['status']=='error'and r['exit_code']==1
x=json.loads(r['output']);assert x=={'ok':False,'stage':'arguments','error':0,'interfaces_queried':0,'file_opens':0,'ioctls':0};observed['invalid-arguments']=x
after=json.loads(op('after-original-stack','exec',argv=[audit,'audit'])['output'])['result'];assert before==after;s['audit_after']=after;R.persist()
health=op('after-health','probe');assert health['detail']['cpus']==8
s.update(phase='small_native_client_refuses_original_G17_before_project_interface_file_or_IOCTL_operations',native_refusals=observed,binary_sha256=v['binary_sha256'],staged_project_bytes=v['bytes'],driver_loaded=False,phone_rebooted=False,firmware_WIM_BCD_GPT_or_boot_image_write=False,native_clock_vote_qualified=False,session=r['session']);R.persist();print(json.dumps({k:s[k]for k in ['phase','staged_project_bytes','driver_loaded','native_clock_vote_qualified','session']}))
