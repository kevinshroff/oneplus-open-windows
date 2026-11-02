"""Audit exported source and receipt consistency; never access a phone or debugger."""
from pathlib import Path
import argparse,hashlib,json

p=argparse.ArgumentParser();p.add_argument('--output',type=Path);a=p.parse_args()
W=Path(__file__).resolve().parent;E=W.parents[1]/'evidence/G64'
J=lambda n:json.loads((E/n).read_text())
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
b=J('helper-build.json');r=J('source-reproduction.json');q=J('WIM-qualified.json');c=J('checkpoint-audit.json')
assert b['binary_sha256']==r['helper_binary_sha256']=='7e490e4cfe999b5a1a08471417fbf14caa13b5e64c9dfe9e9a3c0254ba601203'
assert b['source_files_sha256']==r['source_files_sha256']
for n,h in b['source_files_sha256'].items():assert sha(W/n)==h
assert b['RAM_guard_policy_cases']==r['RAM_guard_cases']==278 and J('helper-policy-tests.json')['passed']
assert sha(E.parent/'G63/package-manifest.json')==b['package_manifest_sha256']=='db82ea3d266206c41401e6274f77a2d763dadf4a93f2687dbf83d70eed253dd9'
assert q['phase']=='retained_verified_audited_trial_and_delta'and q['path_entries']==21760
assert q['only_changed_paths']==['Windows/System32/acpitabl.dat']and q['both_directions_locally_reconstructed']
assert q['no_added_or_removed_paths']and q['changed_path_ACLs_and_attributes_preserved']and q['boot_index']==1
n=J('native-mutating-mode-refusals.json')
assert n['native_modes']==['trust','stage','bind']and not n['setup_mutations_performed']and n['native_RAM_setup_unqualified']
assert n['software_before']==n['software_after']
for mode in n['native_modes']:
    v=n['jobs']['negative-'+mode]['receipt'];assert v['status']=='error'and v['exit_code']==1
    out=json.loads(v['output']);assert not out['ok']and out['error'].startswith('G64 setup requires')
    assert out['result']['environment']['DSDT_bytes']==576 and out['result']['environment']['x_device']==r'\Device\HarddiskVolume6'
u=J('inactive-WIM-update-refusal.json');assert'single-file-update'not in u['jobs']and not u['file_update_executable_invoked']
boot=J('native-recovery-boot.json');files=J('native-recovered-files.json')
assert boot['phase']=='fresh_boot_root_and_all_protected_metadata_verified'and not boot['root']['x_is_ramdisk']
assert boot['all_six_GPTs_byte_identical_to_baseline']and boot['partition_count']==138 and len(boot['GPT_checks'])==6
assert boot['API_DSDT']=={'bytes':576,'sha256':'c8ef19940f424fce18a6e56580493629accb7c59a9ae495cc42c9445029f3e01','exact_expected_table':True}
assert files['phase']=='normal_G17_recovery_full_boot_WIM_and_stack_hashes_verified'and files['session']==boot['session']
for n,h in [('boot_a','f52c793d01d73eb773bc2f442cdf6eefcd6b7ee395e3af290c8147fefd8caa8e'),('boot_b','07dba7ac86e02ea0ff628250991d638da09b8e0680886aee1933df8f56bc4d3b')]:
    assert files[n]['sha256']==h and files[n]['bytes']==201326592 and files[n]['raw_writes']==0
assert files['G18-maintenance']['sha256']=='1db2c5d735281ddcb11f1723bb729753e81a74793a495a83c0bece2ffd26d7e9'
assert files['inactive-G23']['sha256']==q['source_sha256']=='bf8da75a5ff96af9c65fb5f059e6cbb8206595aeeee9c5057e31e31bd4e30250'
code=J('Ntfs-native-code-match.json');rea=J('REA-Ntfs-summary.json');stall=J('native-storage-stall.json')
assert code['passed']and sum(x['bytes']for x in code['native_code_ranges'])==320
assert all(x['exact_code_bytes_match_candidate']for x in code['native_code_ranges'])
assert files['Ntfs_native_file_sha256']==code['candidate_file_sha256']==rea['candidate_sha256']
assert len(rea['procedures'])==2 and all(x['evidence_id'].startswith('ev_')for x in rea['procedures'])
assert rea['provider']=={'id':'ghidra','version':'12.1.4'}
assert not stall['complete_causal_lock_cycle_proved']and not stall['underlying_UFS_fault_proved']and not stall['G63_native_resource_handoff_qualified']
assert c['passed']and c['all21_goal_areas_active']and not c['G63_driver_loaded']and not c['G63_native_resource_handoff_qualified']
assert not c['WIM_native_update_invoked']and not c['BCD_FAT_GPT_firmware_or_boot_image_update_attempted']
assert J('recovery-timeline.json')['old_transfer_final_status']=='previous_session_unknown'
report={'passed':True,'exported_helper_source_and_byte_identical_build_consistent':True,'all_three_native_physical_root_refusals_verified':True,'one_table_image_and_inverse_qualification_receipts_consistent':True,'native_NTFS_stall_and_REA_selected_code_evidence_consistent':True,'fresh_G17_full_protected_recovery_receipts_consistent':True,'native_G63_resource_trial_performed':False,'all21_goal_areas_active':True,'scope':'Public source and receipt consistency. Full WIM, raw FAT/GPT comparison, live code bytes and native execution were separately checked against retained private artifacts; they are not re-executed by this audit.'}
if a.output:a.output.write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report))
