"""Check public source/receipts and independently decode the native608byte report."""
from pathlib import Path
import argparse,hashlib,json,struct

p=argparse.ArgumentParser();p.add_argument('--output',type=Path);a=p.parse_args()
W=Path(__file__).resolve().parent;ROOT=W.parents[1];E=ROOT/'evidence/G65'
J=lambda n:json.loads((E/n).read_text());sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
m=J('updater-build.json');r=J('updater-reproduction.json');old=J('updater-r5-source-baseline.json')
assert m['binary_sha256']==r['binary_sha256']=='a9f338b1059e94bd5a2c1fbc6294561f671c6a79099947a073390d150fa0cb1f'
assert m['sources_sha256']==r['sources_sha256'] and m['passed_tests']==r['passed_tests']==36
rebuild=J('exported-source-rebuild.json')
assert rebuild['binary_sha256']==m['binary_sha256'] and rebuild['sources_sha256']==m['sources_sha256'] and rebuild['passed_tests']==36
src=ROOT/'maintenance/disktool'
for name,h in m['sources_sha256'].items():assert sha(src/name)==h,name
for name,h in old['sources'].items():
 if name!='main_windows.go':assert sha(src/name)==h,name
dispatch='\tif a[0] == "update-trial-wim-ram" && len(a) == 4 && a[3] == "--update-only-inactive-trial-file-from-ram" {\n\t\treturn updateTrialWIMFromRAM(a[1], a[2])\n\t}\n'
main=(src/'main_windows.go').read_text();assert main.count(dispatch)==1
assert hashlib.sha256(main.replace(dispatch,'').encode()).hexdigest()==old['sources']['main_windows.go']
for name,size,h in [('native-RAM-boot.json',576,'c8ef19940f424fce18a6e56580493629accb7c59a9ae495cc42c9445029f3e01'),('native-resource-boot.json',730,'cdc95eadbedcaf60088741e36803b9c96297ccc72afa48b2adb5d9b9c3205ece'),('native-G17-return-boot.json',576,'c8ef19940f424fce18a6e56580493629accb7c59a9ae495cc42c9445029f3e01')]:
 v=J(name)
 assert v['phase']=='fresh_boot_root_and_all_protected_metadata_verified'
 assert v['all_six_GPTs_byte_identical_to_baseline'] and len(v['GPT_checks'])==6 and v['partition_count']==138
 assert v['API_DSDT']=={'bytes':size,'sha256':h,'exact_expected_table':True}
 assert v['root']['x_is_ramdisk']==(name!='native-G17-return-boot.json')
boots=[J(n)['session']for n in ['native-RAM-boot.json','native-resource-boot.json','native-G17-return-boot.json']];assert len(set(boots))==3
t=J('RAM-transfer-proof.json');assert t['phase']=='RAM_journal_large_transfer_and_roundtrip_verified'
assert t['transferred_bytes']==2229676 and t['sha256']=='e41ec3f27b60f4d9cf706b23bd6f879104377fdafe3d12b830fb6ccb228104e8'
assert t['physical_partition_write_calls']==0 and not t['configuration_secrets_exported']
for n in ['maintenance-boot-preparation.json','resource-boot-preparation.json']:
 v=J(n);assert v['phase']=='offline_one_time_BCD_and_FAT_plan_audited_not_activated'
 assert v['G17_default_and_all_original_BCD_keys_values_unchanged'] and v['inverse_exactly_restores_fresh_FAT']
 assert(v['before_BCD_keys'],v['after_BCD_keys'],v['changed_sectors'],v['files_compared'])==(81,82,10,76)
 assert v['FAT_copies_identical'] and v['VBR_512_bytes_unchanged'] and v['fsck_exit']==0
u=J('native-WIM-update.json');assert u['phase']=='native_RAM_controlled_trial_WIM_update_and_full_readback_verified'
assert u['raw_partition_writes']==0 and u['FAT_unchanged'] and u['full_WIM_readback_sha256']=='cbde3b27ab321d054d463e6ebf1c803dea6bb00b3b09419b9c6b8afdeda6aed7'
assert u['update_result']['identity']['raw_writes']==0 and u['update_result']['identity']['journal_root']=='proved RAM'
n=J('native-recorder.json');audit=J('native-resource-audit.json');raw=E/'native-G63-resources.bin';b=raw.read_bytes()
assert len(b)==608 and sha(raw)==audit['sha256']==n['raw_resource_sha256']=='40268d597c91d667f6c888121d592573efd362540a1147a90a6cca18f23eb5b7'
assert struct.unpack_from('<II',b)==(608,1) and b[8:16]==b'OPG63RS1'
assert struct.unpack_from('<10I',b,16)==(26100,8,0,730,1,0,1,0,1,0)
assert struct.unpack_from('<10I',b,56)==(1,1,2,2,20,8,2,2,0,0)
for kind,offset,wanted in [('raw',96,(389,0,389,0xffffffff)),('translated',352,(10,0,2560,255))]:
 mem,irq=b[offset:offset+32],b[offset+32:offset+64]
 assert mem[:4]==bytes([3,1,0,0]) and irq[:4]==bytes([2,1,0,0])
 assert struct.unpack_from('<QI',mem,4)==(0xa90000,0x4000)
 assert struct.unpack_from('<HHIQ',irq,4)==wanted
 assert mem[20:]==irq[20:]==bytes(12) and b[offset+64:offset+256]==bytes(192)
 assert audit['resources'][kind]['memory_descriptor_hex']==mem[:20].hex()
 assert audit['resources'][kind]['interrupt_descriptor_hex']==irq[:20].hex()
assert audit['passed'] and audit['native_resource_handoff_qualified'] and not audit['interrupt_delivery_qualified'] and not audit['functional_SPI_controller_qualified']
assert n['bind_result']['result']['result']['bound'] and not n['bind_result']['result']['result']['reboot_requested']
assert n['certificate_scope']=='RAM-only phone session' and not n['host_trust_changed']
package=json.loads((E.parent/'G63/package-manifest.json').read_text())
assert n['hash_qualified_staged_files']['package.json']==sha(E.parent/'G63/package-manifest.json')
for name,h in package['files'].items():assert n['hash_qualified_staged_files'][name]==h
assert n['hash_qualified_staged_files']['setup']=='7e490e4cfe999b5a1a08471417fbf14caa13b5e64c9dfe9e9a3c0254ba601203'
f=J('native-returned-files.json');assert f['session']==boots[2] and f['original_software_stack_verified']
assert f['RAM_recorder_service_absent_after_return'] and f['final_health']['arch']=='arm64' and f['final_health']['cpus']==8
assert f['RAM_recorder_absence_receipt']['status']=='error' and f['RAM_recorder_absence_receipt']['exit_code']==1
assert 'The system was unable to find the specified registry key or value.' in f['RAM_recorder_absence_receipt']['output']
assert f['software_audit']==json.loads((E.parent/'G64/native-recovered-files.json').read_text())['software_audit']
for name,h in [('boot_a','f52c793d01d73eb773bc2f442cdf6eefcd6b7ee395e3af290c8147fefd8caa8e'),('boot_b','07dba7ac86e02ea0ff628250991d638da09b8e0680886aee1933df8f56bc4d3b')]:
 assert f[name]['sha256']==h and f[name]['bytes']==201326592 and f[name]['raw_writes']==0
assert f['G18-maintenance']['sha256']=='1db2c5d735281ddcb11f1723bb729753e81a74793a495a83c0bece2ffd26d7e9'
assert f['inactive-G63']['sha256']==u['full_WIM_readback_sha256']
c=J('checkpoint.json');assert c['passed'] and c['all21_goal_areas_active'] and c['physical_tests_requested']==0
report={'passed':True,'native608byte_report_independently_decoded':True,'recorded_source_build_and_native_receipts_consistent':True,'old_updater_source_and_dispatch_preserved':True,'three_distinct_boot_sessions_and_protected_return_verified':True,'native_resource_handoff_qualified':True,'interrupt_delivery_qualified':False,'DMA_or_functional_SPI_qualified':False,'all21_goal_areas_active':True,'scope':'Public source/receipt consistency and actual native608byte packet. Full private WIM, FAT/GPT byte comparisons and native commands are not rerun by this audit.'}
if a.output:a.output.write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report))
