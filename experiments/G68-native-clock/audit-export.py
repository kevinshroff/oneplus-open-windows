"""Read-only public source, native byte, image/undo and protected-return audit."""
from pathlib import Path
import argparse,hashlib,json,struct
p=argparse.ArgumentParser();p.add_argument('--output',type=Path);a=p.parse_args()
W=Path(__file__).resolve().parent;ROOT=W.parents[1];E=ROOT/'evidence/G68'
J=lambda n:json.loads((E/n).read_text());sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
for kind in ['setup','updater']:
 m=J(kind+'-build.json');r=J('build-reproduction.json')[kind]
 assert r['fresh_source_copy_byte_identical']and r['sha256']==m['binary_sha256']and r['bytes']==m['bytes']
 key='source_files_sha256'if kind=='setup'else'sources_sha256'
 for n,h in m[key].items():assert sha(W/n if kind=='setup'else W/'updater-source'/n)==h,n
assert J('setup-build.json')['RAM_guard_policy_cases']==278
assert J('updater-build.json')['passed_tests']==38 and J('updater-build.json')['skipped_tests']==0
old=J('updater-source-derivation.json')['prior_sha256']
current=J('updater-build.json')['sources_sha256']
assert all(current[n]==h for n,h in old.items()if n!='wim_ram.go')
image=J('WIM-qualified.json')
assert image['path_entries']==21760 and image['only_changed_paths']==['Windows/System32/acpitabl.dat']
assert image['all_actual_security_descriptors_identical']and image['nonempty_security_descriptors']==21759
assert image['all_attributes_and_link_memberships_identical']and image['both_directions_locally_reconstructed']
assert image['source_sha256']=='cbde3b27ab321d054d463e6ebf1c803dea6bb00b3b09419b9c6b8afdeda6aed7'
assert image['sha256']=='de32242eb883ed45d1d29db52190ef5161da6845cccbad40c7cf821a0866b9dc'and image['bytes']==595963755
assert image['forward_plan_bytes']==2229308 and image['delta_ranges']==1 and image['appended_bytes']==1540656
assert sha(W/'wim-manifest.c')==image['manifest_tool_source_sha256']
update=J('native-image-update.json');assert update['phase']=='native_RAM_controlled_trial_WIM_update_and_full_readback_verified'
assert update['update_result']['before_sha256']==image['source_sha256']and update['update_result']['after_sha256']==image['sha256']
assert update['update_result']['identity']['raw_writes']==0 and update['update_result']['identity']['journal_root']=='proved RAM'
assert update['FAT_unchanged']and update['native_update_receipt']['duration_ms']==56511
for n in ['maintenance-boot-preparation.json','resource-boot-preparation.json']:
 b=J(n);assert b['G17_default_and_all_original_BCD_keys_values_unchanged']and b['before_BCD_keys']==81 and b['after_BCD_keys']==82
 assert b['files_compared']==76 and b['only_changed_file']=='EFI/Microsoft/Boot/BCD'and b['changed_sectors']==10
 assert b['inverse_exactly_restores_fresh_FAT']and b['FAT_copies_identical']and b['fsck_exit']==0 and b['raw_writes']==0
for kind in ['initial','maintenance','resource','physical']:
 b=J('boot-'+kind+'.json');assert b['phase']=='fresh_boot_root_and_all_protected_metadata_verified'
 assert b['all_six_GPTs_byte_identical_to_baseline']and b['partition_count']==138 and len(b['GPT_checks'])==6
 assert sum(t['byte_identical_regions']for t in b['GPT_checks'])==30
 assert b['root']['x_is_ramdisk']==(kind in('maintenance','resource'))
 assert b['API_DSDT']['bytes']==(742 if kind=='resource' else 576)
query=(E/'native-before.bin').read_bytes();raw=(E/'native-cycle.bin').read_bytes()
assert len(query)==len(raw)==1872 and query[:208]==raw[:208]
assert struct.unpack_from('<IIQ18I',raw)==(1872,1,0x314b4c433736504f,26100,8,0,742,1,0,1,0,1,0,1,0,3,3,1,7,3,0)
assert struct.unpack_from('<II',query,208)==(0,0)and not any(query[216:])
assert struct.unpack_from('<II',raw,208)==(1,0)
for start in [88,148]:
 pages=[]
 for i in range(3):
  ty,share,flags,base,n,unused=struct.unpack_from('<BBHQII',raw,start+i*20)
  assert(ty,share,flags,n,unused)==(3,1,0,4096,0);pages.append(base)
 assert set(pages)=={0x118000,0x123000,0x152000}
assert raw[88:148]==raw[148:208]
nonce,code,error,restored,phase,reads,writes,waits,count,dirty,active=struct.unpack_from('<Q10I',raw,216)
assert code==5 and error==phase==dirty==active==0 and restored==1 and(reads,writes,waits,count)==(34,6,1,41)
baseline=(0x40002380,0x80004000,0x80000000,0x100000,0,0x80000002)
assert struct.unpack_from('<6I',raw,264)==struct.unpack_from('<6I',raw,312)==baseline
enabled=struct.unpack_from('<6I',raw,288);assert enabled==(0x44302380,0x4000,0,0x100000,0,0x80000002)
trace=[struct.unpack_from('<4I',raw,336+16*i)for i in range(count)]
assert all(k in(1,2,3)and reg<6 for k,reg,v,phase in trace)
assert[sum(k==i for k,_,_,_ in trace)for i in(1,2,3)]==[reads,writes,waits]
assert[(reg,v)for k,reg,v,_ in trace if k==2]==[(0,v)for v in [0x40102380,0x40302380,0x44302380,0x40302380,0x40102380,0x40002380]]
assert not any(raw[336+16*count:])
clock=J('native-cycle-audit.json');assert clock['passed']and not clock['native_finite_clock_cycle_and_restoration_qualified']
assert clock['native_vote_sequence_and_exact_restore_observed']and clock['policy_refusal_reproduced_from_native_reads']
assert clock['report_before']['sha256']==sha(E/'native-before.bin')and clock['report_after']['sha256']==sha(E/'native-cycle.bin')
assert clock['report_after']['clock']['nonce']==nonce and clock['offline_actual_core_replay']['actual_core_replays_all_native_events_byte_identically']
assert clock['offline_actual_core_replay']['policy_accepted']is False
replay=J('replay-build.json');assert replay['actual_core_byte_identical_replay_passed']and replay['policy_accepted']is False
for n,h in replay['source_sha256'].items():
 p=W.parent/'G67-resource-clock'/Path(n).name if n.startswith('../clock-owner-G67/') else W/n
 assert sha(p)==h,n
facts=J('root-status-source.json');assert facts['sources'][0]['sha256']=='ce642f39b41b2343db307433c53fb283d41ed0b55e2a2e7259d416386f168b2c'
assert facts['model_gap']['old_model_enabled_CMD']=='0x80000000'and facts['model_gap']['native_enabled_CMD']=='0x0'
install=J('native-install.json');assert install['bind_result']['result']['result']['bound']and not install['bind_result']['result']['result']['reboot_requested']
assert install['native_driver_file_sha256']=='41131417c11e69b828c96b225da6c0bdf0028a26a75a8ecfd7cb8d9e6b475beb'
assert install['before_query_result']['ok']and not install['cycle_result']['ok']and install['cycle_result']['code']==5
assert install['post_refusal_cached_query_byte_identical']and install['post_refusal_packet_sha256']==sha(E/'native-cycle.bin')
ret=J('returned-files.json');assert ret['phase']=='normal_G17_recovery_full_boot_WIM_and_stack_hashes_verified'
assert ret['RAM_clock_service_absent_after_return']and ret['original_software_stack_verified']
assert ret['software_audit']==json.loads((E.parent/'G64/native-recovered-files.json').read_text())['software_audit']
assert ret['boot_a']['sha256']=='f52c793d01d73eb773bc2f442cdf6eefcd6b7ee395e3af290c8147fefd8caa8e'
assert ret['boot_b']['sha256']=='07dba7ac86e02ea0ff628250991d638da09b8e0680886aee1933df8f56bc4d3b'
assert ret['inactive-G67']['sha256']==image['sha256']and ret['G18-maintenance']['sha256']=='1db2c5d735281ddcb11f1723bb729753e81a74793a495a83c0bece2ffd26d7e9'
c=J('checkpoint.json');assert c['passed']and c['all21_goal_areas_active']and c['physical_tests_requested']==0
if(E/'manifest.json').exists():
 for entry in J('manifest.json')['files']:
  p=ROOT/entry['path'];assert p.stat().st_size==entry['bytes']and sha(p)==entry['sha256'],entry['path']
r={'passed':True,'native_1872byte_packets_independently_decoded':True,'native_assigned_GCC_resources_qualified':True,'native_votes_and_exact_restore_observed':True,'native_clock_high_level_policy_accepted':False,'ROOT_OFF_policy_refusal_and_model_gap_identified':True,'source_build_image_undo_and_return_receipts_consistent':True,'all21_goal_areas_active':True,'scope':'Read-only public evidence check; no native operations or private binary execution.'}
if a.output:a.output.write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps(r))
