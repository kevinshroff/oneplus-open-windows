"""Undo only hash-identified G51 additions after the owned root is removed."""
from pathlib import Path
import argparse, hashlib, json
from relay import Relay
p=argparse.ArgumentParser();p.add_argument('--phase',required=True,choices=['stage','unimport','undo-include','delete-source-service','audit-after']);a=p.parse_args()
W=Path(__file__).resolve().parent;R=Relay('cleanup-native.json');sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
binary=W/'private/cleanup-build-01/g51-cleanup-arm64.exe';m=json.loads((binary.parent/'build.json').read_text())
assert sha(W/'g51_cleanup.go')==m['source_sha256'] and sha(binary)==m['binary_sha256']
remote=r'X:\OpenG17\payloads\G51-cleanup.exe'
args=[r'X:\OpenG17\payloads\G51-package\package.json',sha(W/'private/package.json')]
assert json.loads((W/'native-qualification.json').read_text())['phase'] in ['owned_root_removed','owned_package_uninstalled']
assert json.loads((W/'vhf-binding-v8.json').read_text())['phase']=='temporary_binding_uninstalled'
def execute(label,argv):
    r=R.op(label,'phone','exec',argv=argv);assert r['status']=='ok' and r.get('exit_code')==0,r
    v=json.loads(r['output']);assert v['ok'],v
    return v['result']
if a.phase=='stage':
    assert R.op('put','phone','put',file=binary,path=remote)['sha256']==sha(binary)
    assert R.op('hash','phone','hash',path=remote)['sha256']==sha(binary)
    R.s['audit_before']=execute('audit-before',[remote,'audit']);v=R.s['audit_before']
    assert v['owned_roots']==0 and v['source_interfaces']==[] and v['processors']==8 and v['inventory']['SM_DIGITIZER']==0
    R.s['phase']='guarded_cleanup_staged_root_and_touch_interface_absent'
elif a.phase=='unimport':
    assert R.s['phase']=='guarded_cleanup_staged_root_and_touch_interface_absent'
    imported=json.loads((W/'dependency-import.json').read_text())['jobs']['import']['receipt'];assert imported['status']=='ok'
    name=json.loads(imported['output'])['result']['published_inf']
    R.s['unimport']=execute('unimport',[remote,'unimport',*args,name]);R.s['phase']='original_include_package_unimported'
elif a.phase=='undo-include':
    assert R.s['phase']=='original_include_package_unimported'
    R.s['undo_include']=execute('undo-include',[remote,'undo-include',*args]);R.s['phase']='original_include_absence_restored'
elif a.phase=='delete-source-service':
    assert R.s['phase']=='original_include_absence_restored'
    R.s['delete_source_service']=execute('delete-source-service',[remote,'delete-source-service',*args]);R.s['phase']='owned_stopped_source_service_removed'
elif a.phase=='audit-after':
    assert R.s['phase']=='owned_stopped_source_service_removed'
    assert json.loads((W/'native-qualification.json').read_text())['phase']=='owned_package_uninstalled'
    R.s['audit_after']=execute('audit-after',[remote,'audit']);v=R.s['audit_after']
    assert v['owned_roots']==0 and v['source_interfaces']==[] and v['processors']==8
    assert not v['source_service']['present'] and not v['inbox_include']['present'] and v['inventory']['SM_DIGITIZER']==0
    before=json.loads((W/'inventory-native.json').read_text())['result'];after=v['inventory']
    assert before['DSDT_sha256']==after['DSDT_sha256'] and before['files']==after['files']
    assert before['services']==after['services']
    R.s['phase']='owned_devices_packages_service_and_inbox_include_removed_baseline_restored'
R.persist()
print(json.dumps({'phase':R.s.get('phase'),'details':R.s.get(a.phase.replace('-','_'))}))
