"""Stage the sealed package via Windows APIs; do not create a device here."""
from pathlib import Path
import json,hashlib
from relay import Relay
W=Path(__file__).resolve().parent;R=Relay('package-native.json');sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();manifest=W/'private/package.json';m=json.loads(manifest.read_text());msha=sha(manifest);assert msha==json.loads((W/'package-host.json').read_text())['manifest_sha256'];base=r'X:\OpenG17\payloads\G51-package'
for name,local in [('OpenG51.sys',W/'private/G51-signed.sys'),('OpenG51.inf',W/'OpenG51.inf'),('OpenG51.cat',W/'private/OpenG51.cat'),('G51-public.cer',W/'private/G51-public.cer'),('package.json',manifest)]:
 expected=msha if name=='package.json'else m['files'][name];assert sha(local)==expected;remote=base+'\\'+name
 assert R.op('put-'+name,'phone','put',file=local,path=remote)['sha256']==expected;assert R.op('hash-'+name,'phone','hash',path=remote)['sha256']==expected
R.s['phase']='sealed_files_verified_on_phone';R.s['manifest_sha256']=msha;R.persist()
client=r'X:\OpenG17\payloads\G51-admin.exe';assert R.op('admin-hash','phone','hash',path=client)['sha256']==json.loads((W/'private/admin-build-03/build.json').read_text())['binary_sha256']
r=R.op('stage-driver-store','phone','exec',argv=[client,'stage',base+r'\package.json',msha]);R.s['stage_result']=r;R.s['phase']='driver_store_stage_returned';R.persist();print(json.dumps({k:r.get(k)for k in['status','exit_code','output','error']},indent=2))
r=R.op('roots-after-stage','phone','exec',argv=[client,'roots']);assert r['status']=='ok';v=json.loads(r['output']);assert v['ok']and not v['result']['owned_roots'];R.s['no_owned_root_created']=True;R.persist()
