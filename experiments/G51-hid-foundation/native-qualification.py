"""One guarded G51 PnP qualification; every action is journaled before waiting."""
from pathlib import Path
import argparse,hashlib,json
from relay import Relay
p=argparse.ArgumentParser();p.add_argument('--phase',required=True,choices=['create','inspect','bind','verify','adopt-binding','empty','remove','uninstall']);a=p.parse_args();W=Path(__file__).resolve().parent;R=Relay('native-qualification.json');sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();manifest=W/'private/package.json';msha=sha(manifest);base=r'X:\OpenG17\payloads\G51-package';client=r'X:\OpenG17\payloads\G51-admin.exe';args=[base+r'\package.json',msha]
staged=json.loads((W/'package-native.json').read_text());assert staged['no_owned_root_created']and staged['manifest_sha256']==msha
meta=json.loads((W/'private/admin-build-03/build.json').read_text());assert meta['source_sha256']==sha(W/'g51_admin.go');assert json.loads((W/'private/driver-model-01/tests.json').read_text())['driver_sha256']==sha(W/'g51_driver.c')
def native(label,mode,mutate=False):
 r=R.op(label,'phone','exec',argv=[client,mode,*args]if mutate else[client,mode]);assert r['status']=='ok'and r.get('exit_code')==0,r;v=json.loads(r['output']);assert v['ok'],v;return v['result']
if a.phase=='create':
 assert R.op('client-hash','phone','hash',path=client)['sha256']==meta['binary_sha256'];R.s['manifest_sha256']=msha;R.s['phone_session']='00000000000000000000000000000000';R.persist();R.s['created']=native('create','create',True);R.s['phase']='owned_root_created';R.persist()
elif a.phase=='inspect':
 R.s['roots']=native('roots-after-create','roots');R.persist();R.s['tree']=native('tree-after-create','tree');R.s['phase']='root_tree_observed';R.persist();print(json.dumps({'roots':R.s['roots'],'tree':R.s['tree']},indent=2))
elif a.phase=='bind':
 assert R.s['phase']=='root_tree_observed'and len(R.s['roots']['owned_roots'])==1 and not(R.s['roots']['owned_roots'][0]['status']&8)and len(R.s['tree']['tree'])==1
 R.s['bind']=native('bind','bind',True);R.s['phase']='owned_root_bound';R.persist()
elif a.phase=='verify':
 R.s['status']=native('status','status');R.persist();s=R.s['status'];assert s['kernel_build']==26100 and s['processors']==8 and s['firmware_match']==s['D0']==s['started']==1 and s['create_status']==s['start_status']==0 and s['max_contacts']==10 and s['report_bytes']==64 and s['descriptor_bytes']==671 and s['mapping_qualified']==0
 R.s['caps']=native('hid-caps','hid-caps');R.persist();rows=R.s['caps']['owned_HID_interfaces'];assert len(rows)==1;v=rows[0];assert v['usage']==4 and v['usage_page']==13 and v['input_report_bytes']==64 and v['feature_report_bytes']==2 and v['max_contact_feature_ok']and v['max_contact_feature']==[2,10],v
 R.s['phase']='Windows_HID_parser_and_feature_verified';R.persist();print(json.dumps({'status':s,'caps':rows},indent=2))
elif a.phase=='adopt-binding':
 assert R.s['phase']=='owned_root_bound'
 v=json.loads((W/'vhf-binding-v8.json').read_text());assert v['phase']=='owned_vhf_child_bound' and v['install']['installed'] and not v['install']['restart_required']
 for label in ['install','post-binding-tree','post-binding-status','post-binding-hid-caps','post-binding-inventory']:
  q=v['jobs'][label]['receipt'];assert q['status']=='ok' and q.get('exit_code')==0 and q['session']=='00000000000000000000000000000000'
 t=v['tree']['tree'];assert len(t)==3 and [x['depth']for x in t]==[0,1,2] and all(x['CM_result']==x['problem']==0 and x['status']&8 for x in t)
 status=v['status'];assert status['firmware_match']==status['D0']==status['started']==1 and status['kernel_build']==26100 and status['processors']==8 and status['create_status']==status['start_status']==status['empty_attempts']==status['empty_accepted']==0 and status['descriptor_bytes']==671 and status['report_bytes']==64 and status['mapping_qualified']==0
 rows=v['hid-caps']['owned_HID_interfaces'];assert len(rows)==1;c=rows[0];assert c['usage_page']==13 and c['usage']==4 and c['input_report_bytes']==64 and c['feature_report_bytes']==2 and c['max_contact_feature_ok'] and c['max_contact_feature']==[2,10]
 assert v['inventory']['SM_DIGITIZER']==193
 before=v['install']['service_before'];after=v['install']['service_after'];assert before['state']==1 and after['state']==4 and {k:x for k,x in before.items()if k!='state'}=={k:x for k,x in after.items()if k!='state'}
 R.s['qualified_binding_evidence']='vhf-binding-v8.json';R.s['status_after_binding']=status;R.s['caps_after_binding']=rows;R.s['SM_DIGITIZER_after_binding']=193;R.s['phase']='Windows_HID_parser_and_feature_verified';R.persist()
elif a.phase=='empty':
 assert R.s['phase']=='Windows_HID_parser_and_feature_verified';R.s['empty']=native('empty','empty');R.persist();s=R.s['empty'];assert s['empty_attempts']==s['empty_accepted']==1 and s['last_submit_status']==0 and s['mapping_qualified']==0;R.s['phase']='one_zero_contact_report_accepted';R.persist();print(json.dumps(s,indent=2))
elif a.phase=='remove':
 R.s['remove']=native('remove','remove',True);R.s['roots_removed']=native('roots-after-remove','roots');R.persist();assert not R.s['roots_removed']['owned_roots'];R.s['phase']='owned_root_removed';R.persist()
elif a.phase=='uninstall':
 assert R.s['phase']=='owned_root_removed';stage=json.loads(staged['stage_result']['output'])['result'];published=stage['published_inf'];r=R.op('uninstall','phone','exec',argv=[client,'uninstall-package',*args,published]);assert r['status']=='ok'and r.get('exit_code')==0,r;R.s['uninstalled']=json.loads(r['output']);R.persist();assert R.s['uninstalled']['ok'];R.s['phase']='owned_package_uninstalled';R.persist()
print(json.dumps({'phase':R.s.get('phase'),'jobs':len(R.s['jobs'])}))
