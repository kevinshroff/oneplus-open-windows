"""Verify G51's source bindings and native evidence; submit no native commands."""
from pathlib import Path
import argparse,hashlib,json,re
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--repository',type=Path,default=Path(__file__).resolve().parents[2]);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists()
R=a.repository;E=R/'evidence/G51';X=R/'experiments/G51-hid-foundation'
j=lambda p:json.loads(p.read_text());sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
n=j(E/'native-evidence.json');q=j(E/'native-qualification.json');v=j(E/'vhf-binding-v8.json');c=j(E/'cleanup-native.json');pn=j(E/'cleanup-final-pnp.json')
assert n['phase']=='baseline_restored_same_session_8CPUs' and q['phase']=='owned_package_uninstalled'
assert c['phase']=='owned_devices_packages_service_and_inbox_include_removed_baseline_restored'
assert pn['phase']=='all_three_G51_OEM_packages_and_HID_devices_absent'
assert n['base_manifest_sha256']==sha(E/'package-manifest.json') and n['child_manifest_sha256']==sha(E/'vhf-package-manifest.json')
assert sha(X/'OpenG51.inf')==j(E/'package-manifest.json')['files']['OpenG51.inf']
assert sha(X/'G51Vhf.inf')==j(E/'vhf-package-manifest.json')['files']['G51Vhf.inf']
assert j(E/'vhf-package-manifest.json')['base_manifest_sha256']==n['base_manifest_sha256']
for name in ['report-model.json','driver-model.json','ABI-model.json','source-object-reproduction.json']:assert j(E/name)['passed']
rm=j(E/'report-model.json');assert rm['cases']==66435 and rm['descriptor_bytes']==671 and rm['input_report_bytes']==64
for name,h in rm['source_sha256'].items():assert sha(X/name)==h
dm=j(E/'driver-model.json');assert dm['cases']==29 and dm['driver_sha256']==sha(X/'g51_driver.c') and dm['protocol_sha256']==sha(X/'g51_protocol.h')
abi=j(E/'ABI-model.json');assert len(abi['cases'])==7 and abi['source_sha256']==sha(X/'g51_admin.go') and abi['protocol_sha256']==sha(X/'g51_protocol.h') and abi['C_response_bytes']==128
build=j(E/'ARM64-build.json');assert len(build['objects'])==2
for r in build['objects']:assert sha(X/r['source'])==r['source_sha256']
for name,h in build['headers'].items():assert sha(X/name)==h
for name,receipt in [('manage','inventory-build.json'),('admin','admin-build.json'),('child','child-build.json'),('dependency','dependency-build.json'),('cleanup','cleanup-build.json')]:assert sha(X/('g51_'+name+'.go'))==j(E/receipt)['source_sha256']
for d in (X/'historical').iterdir():
    meta=j(d/'build.json');source=next(d.glob('*.go'));assert sha(source)==meta['source_sha256']
repro=j(E/'source-object-reproduction.json');assert repro['all2_normalized_ARM64_objects_identical'] and repro['all5_current_Go_helpers_identical'] and repro['native_commands_submitted']==0
for r in repro['Go_helpers']:assert sha(X/r['source'])==r['source_sha256'] and r['byte_identical']
assert v['install']['installed'] and not v['install']['restart_required']
before=v['install']['service_before'];after=v['install']['service_after'];assert before['state']==1 and after['state']==4 and {k:z for k,z in before.items()if k!='state'}=={k:z for k,z in after.items()if k!='state'}
tree=v['tree']['tree'];assert len(tree)==3 and [r['depth'] for r in tree]==[0,1,2] and all(r['CM_result']==r['problem']==0 and r['status']&8 for r in tree)
caps=v['hid-caps']['owned_HID_interfaces'];assert len(caps)==1;cap=caps[0]
assert cap['usage_page']==13 and cap['usage']==4 and cap['input_report_bytes']==64 and cap['feature_report_bytes']==2 and cap['max_contact_feature_ok'] and cap['max_contact_feature']==[2,10]
assert cap['link_collections']==11 and cap['input_button_caps']==20 and cap['input_value_caps']==32
s=q['empty'];assert s['empty_attempts']==s['empty_accepted']==1 and s['last_submit_status']==0 and s['feature_callbacks']==2
assert s['kernel_build']==26100 and s['processors']==8 and s['firmware_match']==s['D0']==s['started']==1 and s['create_status']==s['start_status']==0 and s['mapping_qualified']==0
initial=j(E/'inventory-native.json')['result'];during=v['inventory'];final=c['audit_after']
assert initial['SM_DIGITIZER']==0 and during['SM_DIGITIZER']==193 and final['inventory']['SM_DIGITIZER']==0
assert final['processors']==8 and final['owned_roots']==0 and final['source_interfaces']==[] and not final['source_service']['present'] and not final['inbox_include']['present']
assert initial['files']==during['files']==final['inventory']['files'] and initial['services']==final['inventory']['services']
assert initial['DSDT_sha256']==during['DSDT_sha256']==final['inventory']['DSDT_sha256']==j(X/'binding.json')['DSDT_sha256']
removed=j(E/'remove-disconnected.json');assert removed['phase']=='temporary_binding_removed_without_force_after_owned_descendants' and removed['exact_instance_ids']==[r['id'] for r in tree[1:]]
assert 'no published driver packages were found' in pn['jobs']['packages']['receipt']['output'].lower()
assert 'no devices were found' in pn['jobs']['HID-devices']['receipt']['output'].lower()
sig=j(E/'signature-verification.json');assert sig['signed_driver_sha256']==n['driver_sha256'] and sig['embedded_CMS_signature_cryptographically_verified_by_Windows'] and sig['SHA256_Authenticode_digest_matches_verified_CMS_content'] and sig['all_loadable_sections_byte_identical_before_after_signing']
assert not sig['root_trust_store_changed'] and not sig['private_key_exported'] and not sig['production_trust_or_WHQL_claimed']
for path in ['package-host.json','vhf-package-host.json']:
    pkg=j(E/path);assert pkg['catalog_signature']['CMS_signature_verified'] and not pkg['catalog_signature']['root_store_changed'] and not pkg['catalog_signature']['private_key_exported']
    assert 'Errors:\nNone' in pkg['catalog_creation']['output'].replace('\r\n','\n') and 'Warnings:\nNone' in pkg['catalog_creation']['output'].replace('\r\n','\n')
fail=j(E/'failure-ledger.json');assert len(fail['native_failures'])==7
for row in fail['native_failures']:
    r=j(E/row['journal'])['jobs'][row['label']];assert r['id']==row['job'] and r['receipt']['status']=='error'
for path in ['native-qualification.json','vhf-binding-v8.json','cleanup-native.json','cleanup-final-pnp.json','remove-disconnected.json']:
    for label,row in j(E/path)['jobs'].items():
        r=row['receipt'];assert r['session']==n['phone_session']
        if path=='vhf-binding-v8.json' and label=='uninstall':assert r['status']=='error'
        else:assert r['status']=='ok' and r.get('exit_code',0)==0
# The earlier source-status/parser reads are deliberately retained, including
# the empty pre-binding HID list. The successful observation is the later list.
assert q['caps']['owned_HID_interfaces']==[]
assert q['caps_after_binding']==caps
assert 'MmMapIoSpace' not in (X/'g51_driver.c').read_text() and 'ZwWriteFile' not in (X/'g51_driver.c').read_text()
assert all(not n['scope'][k] for k in n['scope'])
result={'passed':True,'Windows_HID_input_bytes':64,'maximum_contacts_feature':10,'SM_DIGITIZER_transition':[0,193,0],'exactly_one_zero_contact_submit_accepted':True,'native_failures_preserved':7,'baseline_restored_same_session_8CPUs':True,'ARM64_objects_reproduced':2,'current_Go_helpers_reproduced':5,'working_physical_touch_claimed':False,'native_commands_submitted_by_audit':0}
a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
