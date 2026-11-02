"""Read-only source/model/signature/native-byte and protected-return consistency."""
from pathlib import Path
import argparse,hashlib,json,struct
p=argparse.ArgumentParser();p.add_argument('--output',type=Path);a=p.parse_args()
W=Path(__file__).resolve().parent;ROOT=W.parents[1];E=ROOT/'evidence/G69'
J=lambda n:json.loads((E/n).read_text());sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
for name in ['clock-model.json','adapter-model.json','client-policy-model.json']:
 m=J(name);assert m['passed']and m['native_operations']==0
 for n,h in m.get('source_sha256',{}).items():assert sha(W/n)==h,n
assert [J(n)['cases']for n in ['clock-model.json','adapter-model.json','client-policy-model.json']]==[4704,47,250]
assert J('adapter-model.json')['driver_source_sha256']==sha(W/'g69_driver.c')
for name in ['kernel-build.json','client-build.json']:
 m=J(name)
 for n,h in m['headers'].items():assert sha(W/n)==h
 for row in m['objects']:assert sha(W/row['source'])==row['source_sha256']
 assert sha(W/'inputs/g69_binding.h')==m['binding_sha256']
repro=J('source-reproduction.json');assert repro['passed']and repro['ARM64_objects_byte_identical']and repro['all_selected_SDK_files_rehashed']==114
for n,h in repro['source_sha256'].items():assert sha(W/n)==h,n
assert repro['model_cases']==[4704,47,250]
assert sha(E/'MODEL-NOT-NATIVE.bin')==repro['model_packet_sha256']==J('adapter-model.json')['model_packet_sha256']==J('client-policy-model.json')['fixture_sha256']
assert J('relink-reproduction.json')['independent_source_objects_and_both_full_PEs_reproduced']
assert J('setup-reproduction.json')['passed']and J('setup-reproduction.json')['binary_sha256']==J('setup-build.json')['binary_sha256']
for n,h in J('setup-build.json')['source_files_sha256'].items():assert sha(W/n)==h
assert J('setup-build.json')['RAM_guard_policy_cases']==278
pkg=J('package-manifest.json');sig=J('signature-verification.json');cat=J('catalog-signature.json')
assert sha(E/'package-manifest.json')=='718bd9e634d0c5fcf709fc30401a98fc65431578dd8d78fb723fe8267921d56f'
assert pkg['hardware_id']==r'ACPI\OPEN0067'and pkg['interface_guid']=='2f1df03e-a4ab-4e14-a587-32af76b23969'
assert pkg['files']['OpenG69.sys']==sig['signed_driver_sha256']=='9a0fe77bf442031e53f43de66807c76d2317bc5ddca123a17cfdca6b292a3be4'
assert sig['SHA256_Authenticode_digest_matches_verified_CMS_content']and sig['all_loadable_sections_byte_identical_before_after_signing']and sig['REA_Ghidra_import_inventory_matches_PE_imports']
assert not sig['root_trust_store_changed']and not sig['private_key_exported']and not sig['production_trust_or_WHQL_claimed']
assert cat['CMS_signature_verified']and cat['sha256']==pkg['files']['OpenG69.cat']and not cat['root_store_changed']
client=J('client-verification.json');assert client['passed']and client['binary_sha256']=='73c18aaa1367a6bdf8400f0743ed3beb158928a9c7de1c1b9aee33371a92dc64'and client['bytes']==14336
assert client['REA_Ghidra_import_inventory_matches_PE']and len(client['imports'])==18
assert J('REA-imports.json')['artifact_sha256']==sig['signed_driver_sha256']and J('REA-client-imports.json')['artifact_sha256']==client['binary_sha256']
ref=J('native-client-refusals.json');assert ref['audit_before']==ref['audit_after']
for mode in ['query','cycle']:assert ref['native_refusals'][mode]=={'ok':False,'stage':'DSDT-length','error':576,'interfaces_queried':0,'file_opens':0,'ioctls':0}
for kind in ['initial','resource','physical']:
 b=J('boot-'+kind+'.json');assert b['all_six_GPTs_byte_identical_to_baseline']and b['partition_count']==138
 assert sum(c['byte_identical_regions']for c in b['GPT_checks'])==30
 assert b['API_DSDT']['bytes']==(742 if kind=='resource'else 576)and b['root']['x_is_ramdisk']==(kind=='resource')
prep=J('resource-boot-preparation.json');assert prep['before_BCD_keys']==81 and prep['after_BCD_keys']==82 and prep['changed_sectors']==11
assert prep['files_compared']==76 and prep['only_changed_file']=='EFI/Microsoft/Boot/BCD'and prep['inverse_exactly_restores_fresh_FAT']and prep['G17_default_and_all_original_BCD_keys_values_unchanged']and prep['fsck_exit']==0
activation=J('resource-activation.json');assert activation['FAT_apply']['phase']=='verified'and activation['FAT_apply']['sectors_written']==11
q=(E/'native-before.bin').read_bytes();b=(E/'native-cycle.bin').read_bytes();assert len(q)==len(b)==1872 and q[:208]==b[:208]
assert struct.unpack_from('<IIQ18I',b)==(1872,1,0x314b4c433936504f,26100,8,0,742,1,0,1,0,1,0,1,0,3,3,1,7,3,0)
assert struct.unpack_from('<II',q,208)==(0,0)and not any(q[216:])and struct.unpack_from('<II',b,208)==(1,0)
for start in [88,148]:
 pages=[]
 for i in range(3):
  ty,share,flags,base,n,unused=struct.unpack_from('<BBHQII',b,start+i*20)
  assert(ty,share,flags,n,unused)==(3,1,0,4096,0);pages.append(base)
 assert set(pages)=={0x118000,0x123000,0x152000}
assert b[88:148]==b[148:208]
nonce,code,error,restored,phase,reads,writes,waits,count,dirty,active=struct.unpack_from('<Q10I',b,216)
assert code==error==phase==dirty==active==0 and restored==1 and writes==6 and waits<=14 and reads==35+2*waits and count==41+3*waits
baseline=(0x40002380,0x80004000,0x80000000,0x100000,0,0x80000002)
assert struct.unpack_from('<6I',b,264)==struct.unpack_from('<6I',b,312)==baseline
assert struct.unpack_from('<6I',b,288)==(0x44302380,0x4000,0,0x100000,0,0x80000002)
trace=[struct.unpack_from('<4I',b,336+i*16)for i in range(count)]
assert[(reg,v)for k,reg,v,p in trace if k==2]==[(0,v)for v in [0x40102380,0x40302380,0x44302380,0x40302380,0x40102380,0x40002380]]
assert[sum(k==n for k,reg,v,p in trace)for n in(1,2,3)]==[reads,writes,waits]and not any(b[336+16*count:])
cy=J('native-cycle-audit.json');assert cy['passed']and cy['native_finite_clock_cycle_and_restoration_qualified']and cy['correct_active_idle_root_status_observed']
assert cy['report_before']['sha256']==sha(E/'native-before.bin')and cy['report_after']['sha256']==sha(E/'native-cycle.bin')and cy['report_after']['clock']['nonce']==nonce
assert cy['offline_actual_core_replay']['actual_core_replays_all_native_events_byte_identically']and cy['offline_actual_core_replay']['policy_accepted']
replay=J('replay-build.json');assert replay['actual_core_byte_identical_replay_passed']and replay['policy_accepted']and replay['native_packet_sha256']==sha(E/'native-cycle.bin')
for n,h in replay['source_sha256'].items():assert sha(W/n)==h,n
assert sha(E/'native-cycle.bin')!=sha(E/'MODEL-NOT-NATIVE.bin')
inst=J('native-install.json');assert inst['bind_result']['result']['result']['bound']and inst['post_cycle_cached_query_byte_identical']
assert inst['native_driver_file_sha256']==sig['signed_driver_sha256']and inst['cycle_result']['ok']and inst['post_cycle_packet_sha256']==sha(E/'native-cycle.bin')
ret=J('returned-files.json');assert ret['RAM_clock_service_absent_after_return']and ret['original_software_stack_verified']
assert ret['boot_a']['sha256']=='f52c793d01d73eb773bc2f442cdf6eefcd6b7ee395e3af290c8147fefd8caa8e'and ret['boot_b']['sha256']=='07dba7ac86e02ea0ff628250991d638da09b8e0680886aee1933df8f56bc4d3b'
assert ret['inactive-trial']['sha256']=='de32242eb883ed45d1d29db52190ef5161da6845cccbad40c7cf821a0866b9dc'and ret['G18-maintenance']['sha256']=='1db2c5d735281ddcb11f1723bb729753e81a74793a495a83c0bece2ffd26d7e9'
assert ret['software_audit']==json.loads((E.parent/'G64/native-recovered-files.json').read_text())['software_audit']
assert J('checkpoint.json')['all21_goal_areas_active']and J('checkpoint.json')['physical_tests_requested']==0
if(E/'manifest.json').exists():
 for row in J('manifest.json')['files']:
  f=ROOT/row['path'];assert f.stat().st_size==row['bytes']and sha(f)==row['sha256'],row['path']
r={'passed':True,'source_models_build_reproduction_signatures_and_native_packets_consistent':True,'native_G69_resource_admission_finite_clock_cycle_and_restore_qualified':True,'protected_G17_return_verified':True,'production_provider_or_functional_SPI_qualified':False,'all21_goal_areas_active':True,'scope':'Read-only public consistency audit and independent actual native packet decode; no native operation is repeated.'}
if a.output:a.output.write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps(r))
