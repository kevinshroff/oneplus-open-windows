"""Read-only consistency check of G70 public source and actual native evidence."""
from pathlib import Path
import argparse,hashlib,json,re,struct
p=argparse.ArgumentParser();p.add_argument('--output',type=Path);a=p.parse_args();W=Path(__file__).resolve().parent;ROOT=W.parents[1];E=ROOT/'evidence/G70';J=lambda n:json.loads((E/n).read_text());sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
for n,cases in [('clock-model.json',4704),('consumer-model.json',1056),('adapter-model.json',68),('client-policy-model.json',280)]:
 m=J(n);assert m['passed']and m['native_operations']==0 and m['cases']==cases
 for name,h in m.get('source_sha256',{}).items():assert sha(W/name)==h,name
assert J('adapter-model.json')['driver_source_sha256']==sha(W/'g70_driver.c')
for n in ['kernel-build.json','client-build.json']:
 m=J(n)
 for name,h in m['headers'].items():assert sha(W/name)==h
 for row in m['objects']:assert sha(W/row['source'])==row['source_sha256']
 assert sha(W/'inputs/g70_binding.h')==m['binding_sha256']
r=J('source-reproduction.json');assert r['passed']and r['ARM64_objects_byte_identical']and r['SDK_files_rehashed']==114 and r['model_cases']==[4704,1056,68,280]
for n,h in r['source_sha256'].items():assert sha(W/n)==h,n
assert sha(E/'MODEL-NOT-NATIVE.bin')==J('adapter-model.json')['model_packet_sha256']==J('client-policy-model.json')['fixture_sha256']
assert J('relink-reproduction.json')['independent_source_objects_and_both_full_PEs_reproduced']and J('setup-reproduction.json')['passed']
for n,h in J('setup-build.json')['source_files_sha256'].items():assert sha(W/n)==h
for n,h in J('updater-build.json')['sources_sha256'].items():assert sha(W/'updater-source'/n)==h
assert J('updater-build.json')['passed_tests']==38 and J('setup-build.json')['RAM_guard_policy_cases']==278
pkg=J('package-manifest.json');sig=J('signature-verification.json');cat=J('catalog-signature.json');client=J('client-verification.json')
assert sha(E/'package-manifest.json')=='a380536307155d4c9362884ad31aad11a396640d53ac057c9a6978c07050959a'
assert pkg['hardware_id']==r'ACPI\OPEN0070'and pkg['interface_guid']=='2f1df03e-a4ab-4e14-a587-32af76b23970'
assert pkg['files']['OpenG70.sys']==sig['signed_driver_sha256']=='278a8a9a1e9d22eea0cb12dac69bfdfe0b949818f98a10312282dfe6965d5b0d'
assert sig['SHA256_Authenticode_digest_matches_verified_CMS_content']and sig['all_loadable_sections_byte_identical_before_after_signing']and sig['REA_Ghidra_import_inventory_matches_PE_imports']and not sig['root_trust_store_changed']and not sig['private_key_exported']
assert cat['CMS_signature_verified']and cat['sha256']==pkg['files']['OpenG70.cat']
assert client['passed']and client['binary_sha256']=='14fd9b08880ac868e7fd61924cf11079cbb1c5d2173204d43df451d528f292fb'and client['bytes']==16896 and len(client['imports'])==18
assert J('REA-imports.json')['artifact_sha256']==sig['signed_driver_sha256']and J('REA-client-imports.json')['artifact_sha256']==client['binary_sha256']
for kind in ['initial','maintenance','resource','physical']:
 b=J('boot-'+kind+'.json');assert b['all_six_GPTs_byte_identical_to_baseline']and b['partition_count']==138 and sum(x['byte_identical_regions']for x in b['GPT_checks'])==30
 assert b['API_DSDT']['bytes']==(768 if kind=='resource'else 576)and b['root']['x_is_ramdisk']==(kind in('maintenance','resource'))
for name in ['maintenance','resource']:
 p=J(name+'-boot-preparation.json');x=J(name+'-activation.json');assert p['before_BCD_keys']==81 and p['after_BCD_keys']==82 and p['files_compared']==76 and p['only_changed_file']=='EFI/Microsoft/Boot/BCD'and p['G17_default_and_all_original_BCD_keys_values_unchanged']and p['inverse_exactly_restores_fresh_FAT']and p['fsck_exit']==0
 assert x['FAT_apply']['phase']=='verified'and x['FAT_apply']['sectors_written']==p['changed_sectors']
wim=J('WIM-qualified.json');assert wim['only_changed_paths']==['Windows/System32/acpitabl.dat']and wim['path_entries']==21760 and wim['all_actual_security_descriptors_identical']and wim['all_attributes_and_link_memberships_identical']and wim['both_directions_locally_reconstructed']
assert J('native-WIM-update.json')['full_WIM_readback_sha256']==wim['sha256']=='2bfb6b1b9ab14e01d724c69ce26cfd6afb6716cb5ad658b1e3c658b348158694'
q=(E/'native-before.bin').read_bytes();b=(E/'native-cycle.bin').read_bytes();assert len(q)==len(b)==2056 and q[:288]==b[:288]and struct.unpack_from('<II',q,288)==(0,0)and not any(q[296:])and struct.unpack_from('<II',b,288)==(1,0)
assert struct.unpack_from('<IIQ18I',b)==(2056,1,0x314e45473037504f,26100,8,0,768,1,0,1,0,1,0,1,0,5,5,1,15,4,0)
nonce,code,error,restored,phase,reads,writes,waits,count,dirty,active=struct.unpack_from('<Q10I',b,296);assert code==error==phase==dirty==active==0 and restored==1 and writes==6 and waits<=14 and reads==35+2*waits and count==41+3*waits
baseline=(0x40002380,0x80004000,0x80000000,0x100000,0,0x80000002);assert struct.unpack_from('<6I',b,344)==struct.unpack_from('<6I',b,392)==baseline and struct.unpack_from('<6I',b,368)==(0x44302380,0x4000,0,0x100000,0,0x80000002)
trace=[struct.unpack_from('<4I',b,416+16*i)for i in range(count)];assert[(reg,v)for k,reg,v,p in trace if k==2]==[(0,v)for v in[0x40102380,0x40302380,0x44302380,0x40302380,0x40102380,0x40002380]]and not any(b[416+16*count:1952])
pr=struct.unpack_from('<26I',b,1952);assert pr[:6]==(0,20,2,1,1,0)and pr[6:16]==pr[16:]==(0,0,0x102,0x102,0x20102864,0x20104800,0,0,0,0)
cy=J('native-cycle-audit.json');assert cy['passed']and cy['native_bounded_GENI_identity_consumer_qualified']and cy['report_after']['sha256']==sha(E/'native-cycle.bin')and cy['report_before']['sha256']==sha(E/'native-before.bin')and cy['offline_actual_core_replay']['clock_and_probe_bytes_replayed_identically']and not cy['IRQ_delivery_DMA_pinmux_supplies_or_functional_SPI_qualified']
assert sha(E/'native-cycle.bin')!=sha(E/'MODEL-NOT-NATIVE.bin')
i=J('native-install.json');assert i['bind_result']['result']['result']['bound']and i['post_cycle_cached_query_byte_identical']and i['cycle_result']['ok']and i['post_cycle_packet_sha256']==sha(E/'native-cycle.bin')and i['native_driver_file_sha256']==sig['signed_driver_sha256']
ret=J('returned-files.json');assert ret['RAM_clock_service_absent_after_return']and ret['original_software_stack_verified']and ret['all_six_GPTs_and_138_partitions_verified']
assert ret['boot_a']['sha256']=='f52c793d01d73eb773bc2f442cdf6eefcd6b7ee395e3af290c8147fefd8caa8e'and ret['boot_b']['sha256']=='07dba7ac86e02ea0ff628250991d638da09b8e0680886aee1933df8f56bc4d3b'and ret['inactive-trial']['sha256']==wim['sha256']and ret['G18-maintenance']['sha256']=='1db2c5d735281ddcb11f1723bb729753e81a74793a495a83c0bece2ffd26d7e9'
assert ret['software_audit']==json.loads((E.parent/'G64/native-recovered-files.json').read_text())['software_audit']
assert J('checkpoint.json')['all21_goal_areas_active']and J('checkpoint.json')['physical_tests_requested']==0
if(E/'manifest.json').exists():
 for row in J('manifest.json')['files']:
  f=ROOT/row['path'];assert f.stat().st_size==row['bytes']and sha(f)==row['sha256'],row['path']
r={'passed':True,'source_build_model_signature_native_probe_and_protected_return_consistent':True,'bounded_GENI_consumer_qualified':True,'functional_SPI_IRQ_DMA_GPIO_power_qualified':False,'all21_goal_areas_active':True}
if a.output:a.output.write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps(r))
