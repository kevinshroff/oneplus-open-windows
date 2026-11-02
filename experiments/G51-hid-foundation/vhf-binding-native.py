"""Journaled temporary binding: only the VHF child of the owned G51 root."""
from pathlib import Path
import argparse, hashlib, json
from relay import Relay

p=argparse.ArgumentParser()
p.add_argument('--phase',required=True,choices=['payload','stage','probe','install','observe','uninstall'])
a=p.parse_args();W=Path(__file__).resolve().parent
R=Relay('vhf-binding-v8.json')
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
binary=W/'private/child-build-08/g51-child-arm64.exe'
meta=json.loads((binary.parent/'build.json').read_text())
assert meta['source_sha256']==sha(W/'g51_child.go') and meta['binary_sha256']==sha(binary)
manifest=W/'private/vhf-package.json';m=json.loads(manifest.read_text())
assert m['base_manifest_sha256']==sha(W/'private/package.json')
remote=r'X:\OpenG17\payloads\G51-child-v8.exe'
base=r'X:\OpenG17\payloads\G51-vhf-package'
args=[r'X:\OpenG17\payloads\G51-package\package.json',sha(W/'private/package.json'),base+r'\package.json',sha(manifest)]
locals={'G51Vhf.inf':W/'G51Vhf.inf','G51Vhf.cat':W/'private/G51Vhf.cat','G51-public.cer':W/'private/G51-public.cer'}
assert len(m['files'])==3 and all(sha(path)==m['files'][name] for name,path in locals.items())
proof=json.loads((W/'vhf-package-host.json').read_text())
assert proof['catalog_signature']['CMS_signature_verified'] and proof['catalog_signature']['sha256']==sha(locals['G51Vhf.cat'])

def execute(label,argv):
    r=R.op(label,'phone','exec',argv=argv)
    assert r['status']=='ok' and r.get('exit_code')==0,r
    v=json.loads(r['output']);assert v['ok'],v
    return v['result']

if a.phase=='payload':
    prior=json.loads((W/'vhf-binding-native.json').read_text());assert prior['phase']=='sealed_binding_payload_staged' and prior['manifest_sha256']==sha(manifest)
    R.s['payload_parent_journal']='vhf-binding-native.json'
    for name,local,dest in [('helper',binary,remote)]:
        assert R.op('put-'+name,'phone','put',file=local,path=dest)['sha256']==sha(local)
        assert R.op('hash-'+name,'phone','hash',path=dest)['sha256']==sha(local)
    R.s['manifest_sha256']=sha(manifest);R.s['phase']='sealed_binding_payload_staged'
elif a.phase=='stage':
    assert R.s['phase']=='sealed_binding_payload_staged'
    R.s['stage']=execute('stage',[remote,'stage',*args]);R.s['phase']='temporary_binding_in_driver_store'
elif a.phase=='probe':
    assert R.s['phase']=='temporary_binding_in_driver_store'
    R.s['probe']=execute('probe',[remote,'probe',*args]);R.s['phase']='exact_binding_candidate_observed'
elif a.phase=='install':
    assert R.s['phase']=='exact_binding_candidate_observed'
    v=R.s['probe'];assert len(v['compatible_drivers'])==1 and v['compatible_drivers'][0]['provider']=='OnePlus Open Private Lab'
    assert not(v['state_before']&(8|2)) and v['problem_before'] in (0,1,28)
    R.s['install']=execute('install',[remote,'install',*args]);R.s['phase']='owned_vhf_child_bound'
elif a.phase=='observe':
    for mode in ('tree','status','hid-caps','inventory'):
        R.s[mode]=execute('post-binding-'+mode,[r'X:\OpenG17\payloads\G51-admin.exe',mode]);R.persist()
elif a.phase=='uninstall':
    R.s['uninstall']=execute('uninstall',[remote,'uninstall',*args,R.s['stage']['published_inf']]);R.s['phase']='temporary_binding_uninstalled'
R.persist()
print(json.dumps({k:v for k,v in R.s.items() if k!='jobs'},indent=2))
