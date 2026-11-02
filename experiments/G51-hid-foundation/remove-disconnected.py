"""Remove only two recorded G51 descendants, then the exact unused test INF."""
from pathlib import Path, PureWindowsPath
import json
from relay import Relay
W=Path(__file__).resolve().parent;R=Relay('remove-disconnected.json')
q=json.loads((W/'native-qualification.json').read_text());assert q['phase']=='owned_root_removed' and q['roots_removed']['owned_roots']==[]
v=json.loads((W/'vhf-binding-v8.json').read_text());rows=v['tree']['tree'];assert len(rows)==3 and rows[0]['id'].upper()==r'ROOT\ONEPLUSOPENTOUCHG51\0000'
assert [x['depth'] for x in rows]==[0,1,2]
assert rows[1]['id'].upper().startswith('VHF\\HID_DEVICE_SYSTEM_VHF\\') and rows[2]['id'].upper().startswith('HID\\HID_DEVICE_SYSTEM_VHF\\')
published=PureWindowsPath(v['stage']['published_inf']).name
assert published.lower()=='oem2.inf'
tool=r'X:\Windows\System32\pnputil.exe'
R.s['ownership_tree_receipt']=v['jobs']['post-binding-tree']['id'];R.s['exact_instance_ids']=[x['id'] for x in rows[1:]];R.persist()
for row,name in [(rows[2],'HID-TLC'),(rows[1],'VHF')]:
    inst=row['id'];r=R.op('before-'+name,'phone','exec',argv=[tool,'/enum-devices','/disconnected','/instanceid',inst,'/drivers'])
    assert r['status']=='ok' and r.get('exit_code')==0,r
    text=r['output'].lower();assert inst.lower() in text and 'disconnected' in text
    expected='input.inf' if row['depth']==2 else published.lower();assert expected in text
    r=R.op('remove-'+name,'phone','exec',argv=[tool,'/remove-device',inst]);assert r['status']=='ok' and r.get('exit_code')==0,r
    assert 'successfully' in r['output'].lower(),r
    r=R.op('after-'+name,'phone','exec',argv=[tool,'/enum-devices','/instanceid',inst]);assert r['status']=='ok' and r.get('exit_code')==0,r
    assert 'no devices were found' in r['output'].lower(),r
R.s['phase']='two_recorded_disconnected_children_removed';R.persist()
assert R.op('binding-hash','phone','hash',path=str(PureWindowsPath('X:/Windows/INF')/published))['sha256']==json.loads((W/'private/vhf-package.json').read_text())['files']['G51Vhf.inf']
r=R.op('delete-unused-binding','phone','exec',argv=[tool,'/delete-driver',published]);assert r['status']=='ok' and r.get('exit_code')==0,r
assert 'successfully' in r['output'].lower(),r
R.s['phase']='temporary_binding_removed_without_force_after_owned_descendants';R.persist()
print(json.dumps({'phase':R.s['phase'],'owned_descendants':2,'published_inf':published}))
