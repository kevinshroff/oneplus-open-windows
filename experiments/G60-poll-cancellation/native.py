"""Durable, separate G59 native phases. Live input is never repeated on timeout."""
from pathlib import Path
import argparse,hashlib,json,subprocess,sys
from relay import Relay
W=Path(__file__).resolve().parent;p=argparse.ArgumentParser();p.add_argument('--phase',choices=['initialize','files','stage-root','create','bind-root','stage-child','probe-child','bind-child','verify','remove','delete-service','uninstall-root','audit-after'],required=True);p.add_argument('--run',choices=['idle-stop-v2'],default='idle-stop-v2');a=p.parse_args();suffix='-'+a.run;R=Relay('native-qualification'+suffix+'.json');s=R.s;sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();base=r'X:\OpenG17\payloads';root=base+'\\G60'+suffix+'-package';child=base+'\\G60'+suffix+'-vhf-package'
admin=base+r'\G60-idle-admin-v2.exe';kid=base+r'\G59-child.exe';cleanup=base+r'\G59-cleanup.exe'
subprocess.run([sys.executable,str(W/'preflight.py')],check=True,capture_output=True,text=True)
def op(label,action,**kw):
 r=R.op(label,'phone',action,**kw);assert r['status']=='ok'and r.get('exit_code',0)==0,r;return r
def native(label,argv):
 r=op(label,'exec',argv=argv);q=json.loads(r['output']);assert q['ok'],q;return q['result']
def save():R.persist()
def rootargs():return[root+r'\package.json',sha(W/'private/package.json')]
def childargs():return[*rootargs(),child+r'\vhf-package.json',sha(W/'private/vhf-package.json')]
if a.phase=='initialize':
 assert not s.get('phase'),'Initialization must not reset an existing native phase'
 prep=json.loads((W/'native-preparation-v2.json').read_text());assert prep['phase']=='reused_receiver_selftest_new_idle_helper_and_baseline_verified'
 s['baseline']=prep['baseline'];s['audit_before']=prep['audit_before'];
 s['baseline']=native('fresh-baseline',[admin,'inventory']);s['audit_before']=native('fresh-audit-before',[cleanup,'audit']);v=s['audit_before'];assert v['owned_roots']==0 and v['source_interfaces']==[]and not v['source_service']['present']and not v['inbox_include']['present']and v['inventory']['SM_DIGITIZER']==0 and s['baseline']['files']==prep['baseline']['files']and s['baseline']['services']==prep['baseline']['services']
 s.update(phase='helpers_verified_original_input_baseline_saved',phone_session='00000000000000000000000000000000');save()
elif a.phase=='files':
 assert s['phase']=='helpers_verified_original_input_baseline_saved'
 for kind,folder,names,manifest_name,journal in [('root',root,['OpenG59.sys','OpenG59.inf','OpenG59.cat','G59-public.cer'],'package.json','package-root-host.json'),('child',child,['G59Vhf.inf','G59Vhf.cat','G59-public.cer'],'vhf-package.json','package-child-host.json')]:
  manifest=W/'private'/manifest_name;m=json.loads(manifest.read_text());assert sha(manifest)==json.loads((W/journal).read_text())['manifest_sha256']
  for name in names+[manifest_name]:
   local=manifest if name==manifest_name else W/'private/G59-signed.sys'if name=='OpenG59.sys'else W/name if name.endswith('.inf')else W/'private'/name
   expected=sha(manifest)if name==manifest_name else m['files'][name];assert sha(local)==expected;remote=folder+'\\'+name
   assert op('put-'+kind+'-'+name,'put',file=local,path=remote)['sha256']==expected;assert op('hash-'+kind+'-'+name,'hash',path=remote)['sha256']==expected
 s['phase']='sealed_root_child_payloads_verified_on_phone';save()
elif a.phase=='stage-root':
 assert s['phase']=='sealed_root_child_payloads_verified_on_phone'
 assert json.loads((W/'native-preparation-v2.json').read_text())['phase']=='reused_receiver_selftest_new_idle_helper_and_baseline_verified'
 s['root_stage']=native('stage-root',[admin,'stage',*rootargs()]);s['roots_after_stage']=native('roots-after-stage',[admin,'roots']);assert not s['roots_after_stage']['owned_roots'];s['phase']='root_package_staged_no_device';save()
elif a.phase=='create':
 assert s['phase']=='root_package_staged_no_device'
 s['created']=native('create',[admin,'create',*rootargs()]);save();s['roots_created']=native('roots-created',[admin,'roots']);s['tree_created']=native('tree-created',[admin,'tree']);save()
 assert len(s['roots_created']['owned_roots'])==1 and len(s['tree_created']['tree'])==1 and not(s['roots_created']['owned_roots'][0]['status']&8)
 s['phase']='one_owned_root_created_unbound';save()
elif a.phase=='bind-root':
 assert s['phase']=='one_owned_root_created_unbound'
 s['root_bound']=native('bind-root',[admin,'bind',*rootargs()]);save();assert not s['root_bound']['reboot_requested']
 s['root_status']=native('root-status',[admin,'status']);s['tree_root']=native('tree-root',[admin,'tree']);s['children_root']=native('children-root',[kid,'describe']);save()
 v=s['root_status'];assert v['firmware_match']==v['D0']==v['started']==1 and v['kernel_build']==26100 and v['processors']==8 and v['create_status']==v['start_status']==v['live_attempts']==0 and v['descriptor_bytes']==811 and v['report_bytes']==64
 rows=s['children_root']['owned_descendants'];assert len(rows)==1 and any(x.upper()==r'OPENLAB\ONEPLUSOPENTOUCHG59'for x in rows[0]['hardware_ids'])
 s['phase']='root_started_unique_VHF_child_observed_no_input';save()
elif a.phase in['stage-child','probe-child','bind-child']:
 phase={'stage-child':'root_started_unique_VHF_child_observed_no_input','probe-child':'unique_child_package_staged','bind-child':'single_exact_child_binding_candidate'}[a.phase];assert s['phase']==phase
 mode={'stage-child':'stage','probe-child':'probe','bind-child':'install'}[a.phase];s[a.phase.replace('-','_')]=native(a.phase,[kid,mode,*childargs()]);save()
 if mode=='install':assert s['bind_child']['installed']and not s['bind_child']['restart_required']
 s['phase']={'stage':'unique_child_package_staged','probe':'single_exact_child_binding_candidate','install':'owned_VHF_child_bound'}[mode];save()
elif a.phase=='verify':
 assert s['phase']=='owned_VHF_child_bound'
 s['session_ready']=native('session-ready',[admin,'session']);assert s['session_ready']['state']==s['session_ready']['starts']==s['session_ready']['hardware_calls']==s['session_ready']['result_ready']==0
 s['status_ready']=native('status-ready',[admin,'status']);s['tree_ready']=native('tree-ready',[admin,'tree']);s['children_ready']=native('children-ready',[kid,'describe']);s['caps_ready']=native('caps-ready',[admin,'hid-caps']);s['inventory_ready']=native('inventory-ready',[admin,'inventory']);s['audit_ready']=native('audit-ready',[cleanup,'audit']);save()
 tree=s['tree_ready']['tree'];assert len(tree)==3 and [x['depth']for x in tree]==[0,1,2]and all(x['CM_result']==x['problem']==0 and x['status']&8 for x in tree)
 rows=s['caps_ready']['owned_HID_interfaces'];assert len(rows)==1;c=rows[0];assert c['usage']==4 and c['usage_page']==13 and c['input_report_bytes']==64 and c['feature_report_bytes']==2 and c['max_contact_feature_ok']and c['max_contact_feature']==[2,10]
 for usage,logical,physical in[(48,22680,1450),(49,24400,1350)]:
  axes=[v for v in c['input_values']if v['usage_page']==1 and v['usage_or_min']==usage];assert len(axes)==10
  assert all(v['report_id']==1 and v['bit_size']==16 and v['absolute']==1 and v['is_range']==0 and v['logical_min']==v['physical_min']==0 and v['logical_max']==logical and v['physical_max']==physical and v['units']==0x11 and v['units_exponent_raw']&15==14 for v in axes)
 v=s['status_ready'];assert v['firmware_match']==v['D0']==v['started']==1 and v['live_attempts']==v['reports_accepted']==v['reports_submitted']==v['accepted_mask']==0 and s['inventory_ready']['SM_DIGITIZER']==193
 assert s['inventory_ready']['files']==s['baseline']['files']
 assert s['audit_ready']['owned_roots']==1 and len(s['audit_ready']['source_interfaces'])==1 and s['audit_ready']['source_service']['present']
 s['phase']='Windows_HID_parser_physical_axes_and_owned_tree_verified_no_input';save()
elif a.phase=='remove':
 live=json.loads((W/('live-native'+suffix+'.json')).read_text());assert live['hardware_and_power_restoration_verified']
 assert s.get('created',{}).get('created'), 'Only the recorded owned root may be removed'
 s['removed']=native('remove-root',[admin,'remove',*rootargs()]);s['roots_removed']=native('roots-removed',[admin,'roots']);save();assert not s['roots_removed']['owned_roots'];s['phase']='owned_root_removed';save()
elif a.phase=='delete-service':
 assert s['phase']=='owned_root_removed'
 s['source_deleted']=native('delete-source-service',[cleanup,'delete-source-service',*rootargs()]);s['phase']='owned_stopped_source_service_deleted';save()
elif a.phase=='uninstall-root':
 assert s['phase']=='owned_stopped_source_service_deleted'
 name=Path(s['root_stage']['published_inf'].replace('\\','/')).name;s['root_uninstalled']=native('uninstall-root',[admin,'uninstall-package',*rootargs(),name]);s['phase']='owned_root_package_uninstalled';save()
elif a.phase=='audit-after':
 assert s['phase']=='owned_root_package_uninstalled'
 s['audit_after']=native('audit-after',[cleanup,'audit']);save();v=s['audit_after']
 assert v['owned_roots']==0 and v['source_interfaces']==[]and not v['source_service']['present']and not v['inbox_include']['present']and v['processors']==8 and v['inventory']['SM_DIGITIZER']==0
 assert s['baseline']['DSDT_sha256']==v['inventory']['DSDT_sha256']and s['baseline']['files']==v['inventory']['files']and s['baseline']['services']==v['inventory']['services']
 q=op('probe-end','probe');assert q['detail']['cpus']==8 and q['detail']['arch']=='arm64';s['phase']='owned_input_devices_packages_service_removed_original_baseline_restored';save()
print(json.dumps({'phase':s.get('phase'),'jobs':len(s['jobs'])}))
