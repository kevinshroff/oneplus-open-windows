"""Offline verification of actual Windows consumer delivery and exact owned undo."""
from pathlib import Path
import argparse,hashlib,json
p=argparse.ArgumentParser();p.add_argument('--repository',type=Path,default=Path(__file__).resolve().parents[2]);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();R=a.repository;E=R/'evidence/G55';X=R/'experiments/G55-windows-input';j=lambda p:json.loads(p.read_text());sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
n=j(E/'native-evidence.json');replay=j(E/'replay-evidence.json');ready=j(E/'receiver-ready.json');done=j(E/'receiver-done.json');qual=j(E/'receiver-qualification.json')
assert n['phase']=='owned_input_devices_packages_service_removed_original_baseline_restored'and replay['phase']=='native_Windows_consumer_down_move_up_and_owned_source_verified'
assert ready['Token']==done['token']==replay['token']and ready['Foreground']and ready['DPIAware']and ready['Width']==2440 and ready['Height']==2268
assert qual['owned_foreground_verified']and qual['DPI_aware']and done['window_closed']and done['dropped']==0 and done['mode']=='replay'and 8000<=done['tick']-ready['Tick']<15000
child=done['admin'];assert child['Started']and child['ExitCode']==0 and not child['Error'];response=json.loads(child['Output']);assert response['ok'];submitted=response['result']
for s in[submitted,replay['after']]:
 assert s['build']=='G55-replay1'and s['processors']==8 and s['kernel_build']==26100 and s['firmware_match']==s['D0']==s['started']==1
 assert s['replay_attempts']==s['replay_complete']==1 and s['replay_accepted']==s['replay_submitted']==s['accepted_generation']==4
 assert s['replay_error']==s['last_submit_status']==s['accepted_mask']==s['cleanup_attempted']==s['cleanup_accepted']==0
assert submitted['owned_receiver_verified_immediately_before_submit']['Window']==ready['Window']
events=[json.loads(v)for v in(E/'receiver-events.jsonl').read_text().splitlines()if v.strip()];touch=[v for v in events if v.get('GetPointerInfo_ok')and v['pointer']['Type']==2]
assert [v['message']for v in touch]==['0x249','0x246','0x245','0x245','0x247','0x24a']
assert len({v['pointer']['ID']for v in touch})==len({v['pointer']['Source']for v in touch})==1
assert all(v['pointer']['Target']==v['window']==ready['Window']and v['pointer_id_wparam']==v['pointer']['ID']and v['pointer']['History']==1 and'history_error'not in v for v in touch)
rows=[v for v in touch if v['message']in['0x246','0x245','0x247']];assert len(rows)==4 and [v['pointer']['Frame']for v in rows]==[1,2,3,4]
assert all(rows[i]['pointer']['Performance']<rows[i+1]['pointer']['Performance']for i in range(3))
for v in rows[:3]:assert v['pointer']['Flags']&4 and v['pointer']['Flags']&0x4000
assert rows[0]['pointer']['Flags']&0x10000 and rows[-1]['pointer']['Flags']&0x40000 and rows[-1]['pointer']['Flags']&0x4000 and not(rows[-1]['pointer']['Flags']&4)
raw=[(10989,12328),(19107,2967),(19781,21559),(19781,21559)];errors=[]
for v,(x,y)in zip(rows,raw):
 px=y/24400*2440;py=(1-x/22680)*2268;hx=y/24400*14500;hy=(1-x/22680)*13500;got=v['pointer'];error=max(abs(got['RawPixel']['X']-px),abs(got['RawPixel']['Y']-py));assert error<1;errors.append(error)
 assert abs(got['RawHimetric']['X']-hx)<2 and abs(got['RawHimetric']['Y']-hy)<2
assert rows[-1]['pointer']['RawPixel']==rows[-2]['pointer']['RawPixel']
caps=n['caps_ready']['owned_HID_interfaces'];assert len(caps)==1;c=caps[0];assert c['usage_page']==13 and c['usage']==4 and c['input_report_bytes']==64 and c['feature_report_bytes']==2 and c['max_contact_feature']==[2,10]and c['max_contact_feature_ok']
assert all(v['source_device_name'].casefold()==c['interface_path'].casefold()for v in touch)
for usage,logical,physical in[(48,22680,1450),(49,24400,1350)]:
 axes=[v for v in c['input_values']if v['usage_page']==1 and v['usage_or_min']==usage];assert len(axes)==10
 assert all(v['logical_min']==v['physical_min']==0 and v['logical_max']==logical and v['physical_max']==physical and v['units']==17 and v['units_exponent_raw']&15==14 and v['bit_size']==16 and v['report_id']==1 for v in axes)
tree=n['tree_ready']['tree'];assert len(tree)==3 and [v['depth']for v in tree]==[0,1,2]and all(v['CM_result']==v['problem']==0 and v['status']&8 for v in tree)
identity=j(E/'vhf-identity-qualified.json');observed=identity['observed_child'];assert observed['hardware_ids']==['HID_DEVICE_SYSTEM_VHF',r'OPENLAB\ONEPLUSOPENTOUCHG55']and observed['instance'].startswith('OPENLAB\\ONEPLUSOPENTOUCHG55\\')
assert sha(R/'evidence/G53/vhf-identity-REA.json')==identity['REA_reference_sha256']and identity['native_vhf_sys_sha256']==next(v['sha256']for v in n['baseline']['files']if v['path'].lower().endswith('vhf.sys'))
removed=j(E/'owned-descendant-removal.json');assert removed['phase']=='two_exact_owned_descendants_and_unused_child_package_removed_without_force'and removed['exact_instance_ids']==[v['id']for v in tree[1:]]
assert removed['jobs']['binding-hash']['receipt']['sha256']==j(E/'child-manifest.json')['files']['G55Vhf.inf']
for label in ['remove-TLC','remove-VHF','delete-unused-binding']:assert removed['jobs'][label]['receipt']['status']=='ok'and removed['jobs'][label]['receipt']['exit_code']==0
after=n['audit_after'];before=n['baseline'];assert after['owned_roots']==0 and after['source_interfaces']==[]and not after['source_service']['present']and not after['inbox_include']['present']and after['processors']==8
assert before['DSDT_sha256']==after['inventory']['DSDT_sha256']and before['files']==after['inventory']['files']and before['services']==after['inventory']['services']and before['SM_DIGITIZER']==after['inventory']['SM_DIGITIZER']==0 and n['inventory_ready']['SM_DIGITIZER']==193
assert n['jobs']['probe-end']['receipt']['detail']['cpus']==8
test=j(E/'receiver-selftest.json');assert test['phase']=='owned_fullscreen_foreground_guard_wrong_PID_refusal_finite_closure_passed'and test['qualification']['wrong_PID_refused']=='owned receiver is not the foreground window'and test['done']['driver_requests_submitted']==0 and test['done']['window_closed']
failed=j(E/'initial-launcher-failure.json');assert failed['jobs']['ready']['receipt']['status']=='error'and failed['jobs']['diagnose-worker-log']['receipt']['sha256']==hashlib.sha256(b'').hexdigest()and failed['recorded_worker_terminal']['process_absent']
assert j(E/'failed-launcher-build.json')['source_sha256']==sha(E/'failed-launcher-source.go.txt')
for f,count in [('report-model.json',66435),('replay-model.json',27),('driver-model.json',37),('ABI-model.json',7)]:
 v=j(E/f);assert v['passed']and(len(v['cases'])if isinstance(v['cases'],list)else v['cases'])==count
 if isinstance(v.get('source_sha256'),dict):
  for name,h in v['source_sha256'].items():assert sha(X/name)==h
assert j(E/'driver-model.json')['driver_sha256']==sha(X/'g55_driver.c')and j(E/'driver-model.json')['protocol_sha256']==sha(X/'g55_protocol.h')and j(E/'ABI-model.json')['source_sha256']==sha(X/'g55_admin.go')
build=j(E/'build.json');assert len(build['ARM64_compilation']['objects'])==5
for v in build['ARM64_compilation']['objects']:assert sha(X/v['source'])==v['source_sha256']
for name,h in build['ARM64_compilation']['headers'].items():assert sha(X/name)==h
for name,v in build['helpers'].items():assert sha(X/('g55_'+name+'.go'))==v['source_sha256']
for v in j(E/'core-provenance.json')['cores']:
 p=X/v['new'];old=R/'experiments/G54-release-reader'/Path(*Path(v['qualified_source']).parts[-2:]);assert sha(p)==v['new_sha256']and sha(old)==v['qualified_source_sha256']
 normalized=p.read_text().replace('G55','G54').replace('g55_lifecycle','g54_lifecycle').replace('g55_raw','g54_report').replace('OPEN_G54_RAW_H','OPEN_G54_REPORT_H')
 if p.name=='g55_lifecycle.c':normalized=normalized.replace('"g54_report.h"','"../reader-G54/g54_report.h"')
 assert normalized==old.read_text()
signature=j(E/'signature-verification.json');assert signature['SHA256_Authenticode_digest_matches_verified_CMS_content']and not signature['root_trust_store_changed']and not signature['production_trust_or_WHQL_claimed']
assert signature['signed_driver_sha256']==j(E/'root-manifest.json')['files']['OpenG55.sys']
assert j(E/'source-object-reproduction.json')['all_five_ARM64_objects_identical']and j(E/'source-object-reproduction.json')['all_five_Go_helpers_identical']
out={'passed':True,'native_Windows_application_DOWN_MOVE_MOVE_UP_verified':True,'all_three_saved_positions_error_below_one_pixel':True,'maximum_pixel_error':max(errors),'physical_descriptor_units_also_confirmed_by_native_HIMETRIC':True,'same_pointer_and_exact_owned_HID_source':True,'release_at_last_accepted_coordinates':True,'reports_accepted':4,'one_replay_invocation':True,'full_captured_driver_service_baseline_restored_and_owned_nodes_packages_removed':True,'same_boot_8CPUs':True,'continuous_live_physical_touch_qualified':False,'coalesced_history_branch_native_qualified':False,'native_commands_submitted_by_audit':0};a.output.write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(out))
