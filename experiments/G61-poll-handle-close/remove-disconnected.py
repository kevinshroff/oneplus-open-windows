"""Remove only the two recorded G59 descendants and unused exact child INF."""
from pathlib import Path,PureWindowsPath
import hashlib,json
from relay import Relay
import argparse
p=argparse.ArgumentParser();p.add_argument('--run',choices=['idle-close'],default='idle-close');a=p.parse_args();suffix='-'+a.run
W=Path(__file__).resolve().parent;R=Relay('remove-disconnected'+suffix+'.json');q=json.loads((W/('native-qualification'+suffix+'.json')).read_text());assert q['phase']=='owned_root_removed'and not q['roots_removed']['owned_roots'];rows=q['tree_ready']['tree'];assert len(rows)==3 and [v['depth']for v in rows]==[0,1,2]
assert rows[0]['id'].casefold()==q['created']['instance'].casefold()
assert rows[1]['id'].upper().startswith('OPENLAB\\ONEPLUSOPENTOUCHG59\\')and rows[2]['id'].upper().startswith('HID\\ONEPLUSOPENTOUCHG59\\')
published=PureWindowsPath(q['stage_child']['published_inf']).name;expected=json.loads((W.parent/'contact-cancel-G60/private/vhf-package.json').read_text())['files']['G59Vhf.inf'];tool=r'X:\Windows\System32\pnputil.exe'
R.s.update(ownership_tree_job=q['jobs']['tree-ready']['id'],exact_instance_ids=[v['id']for v in rows[1:]],published_inf=published);R.persist()
def op(label,argv):
 r=R.op(label,'phone','exec',argv=argv);assert r['status']=='ok'and r.get('exit_code',0)==0,r;return r
for row,name in[(rows[2],'TLC'),(rows[1],'VHF')]:
 inst=row['id'];r=op('before-'+name,[tool,'/enum-devices','/disconnected','/instanceid',inst,'/drivers']);text=r['output'].lower();assert inst.lower()in text and'disconnected'in text
 assert ('input.inf'if row['depth']==2 else published.lower())in text
 r=op('remove-'+name,[tool,'/remove-device',inst]);assert'successfully'in r['output'].lower()
 r=op('after-'+name,[tool,'/enum-devices','/instanceid',inst]);assert'no devices were found'in r['output'].lower()
r=R.op('binding-hash','phone','hash',path=str(PureWindowsPath('X:/Windows/INF')/published));assert r['sha256']==expected
r=op('delete-unused-binding',[tool,'/delete-driver',published]);assert'successfully'in r['output'].lower()
R.s['phase']='two_exact_owned_descendants_and_unused_child_package_removed_without_force';R.persist();print(json.dumps({'phase':R.s['phase'],'descendants':2,'published_inf':published}))
