"""Read-only public audit of source, bounded native bytes and curated receipts."""
from pathlib import Path
import argparse, hashlib, json, struct
from lifecycle_trace import decode_trace

parser = argparse.ArgumentParser()
parser.add_argument('--output', type=Path)
args = parser.parse_args()
W = Path(__file__).resolve().parent
ROOT = W.parents[1]
E = ROOT / 'evidence/G66'
J = lambda n: json.loads((E / n).read_text())
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()

builds = [J(n) for n in ('helper-build.json', 'helper-clean-rebuild.json',
                         'helper-exported-source-rebuild.json')]
for build in builds:
    assert build['binary_sha256'] == 'b0764da8c2943af6e684ee29cfc3ef801ce5ad2eae48b4a926972f8afa6b40ab'
    assert build['bytes'] == 2499072 and build['guard_cases'] == 63
    assert build['native_operations'] == 0 and build['target'] == 'windows/arm64'
    assert build['source_sha256'] == builds[0]['source_sha256']
    for name, digest in build['source_sha256'].items():
        assert sha(W / name) == digest, name
assert J('helper-tests.json') == {'passed': True, 'cases': 63, 'native_operations': 0}
api = J('API-source.json')
assert api['observed_macros']['CM_DISABLE_UI_NOT_OK'] == api['CM_disable_flags_used'] == 4
assert api['observed_macros']['CM_DISABLE_PERSIST'] == 8 and api['CM_enable_flags_used'] == 0

fresh = J('fresh-FAT-reconstruction.json')
assert fresh['phase'] == 'fresh_complete_FAT_reconstructed_from_actual_small_reads_and_verified_whole_hash'
assert fresh['bytes'] == 268435456 and fresh['native_raw_bytes_captured'] == 40960
assert fresh['sha256'] == fresh['reconstructed_sha256'] == fresh['expected_whole_sha256'] == '846e65f5ddaf4c3c0a95177f0548815d900b6c214d1e6ffb880e810fc334429f'
assert fresh['raw_writes'] == 0 and fresh['unread_bytes_proved_by_matching_whole_SHA256']
assert sum(length for _, length in fresh['read_ranges']) == 40960
assert len(fresh['fresh_native_whole_hashes']) == 2
for record in fresh['fresh_native_whole_hashes']:
    assert record['sha256'] == fresh['sha256'] and record['bytes'] == fresh['bytes'] and record['raw_writes'] == 0
prep = J('one-time-boot-preparation.json')
assert (prep['before_BCD_keys'], prep['after_BCD_keys'], prep['changed_sectors'], prep['files_compared']) == (81, 82, 10, 76)
assert prep['only_changed_file'] == 'EFI/Microsoft/Boot/BCD'
assert prep['G17_default_and_all_original_BCD_keys_values_unchanged'] and prep['inverse_exactly_restores_fresh_FAT']
assert prep['FAT_copies_identical'] and prep['VBR_512_bytes_unchanged'] and prep['fsck_exit'] == 0
activation = J('native-boot-activation.json')
assert activation['FAT_apply']['sectors_written'] == 10 and activation['FAT_apply']['phase'] == 'verified'
assert activation['FAT_apply']['before_sha256'] == prep['before_sha256'] == fresh['sha256']
assert activation['FAT_apply']['after_sha256'] == prep['after_sha256']

boots = [J(n) for n in ('native-resource-boot.json', 'native-G17-return-boot.json')]
assert boots[0]['session'] != boots[1]['session']
for boot, size, digest, ram in [
    (boots[0], 730, 'cdc95eadbedcaf60088741e36803b9c96297ccc72afa48b2adb5d9b9c3205ece', True),
    (boots[1], 576, 'c8ef19940f424fce18a6e56580493629accb7c59a9ae495cc42c9445029f3e01', False)]:
    assert boot['phase'] == 'fresh_boot_root_and_all_protected_metadata_verified'
    assert boot['root']['x_is_ramdisk'] == ram and boot['all_six_GPTs_byte_identical_to_baseline']
    assert boot['API_DSDT'] == {'bytes': size, 'sha256': digest, 'exact_expected_table': True}
    assert len(boot['GPT_checks']) == 6 and sum(x['byte_identical_regions'] for x in boot['GPT_checks']) == 30
    assert boot['partition_count'] == sum(x['partition_count'] for x in boot['GPT_checks']) == 138

preflight = J('pnp-preflight.json')
assert preflight['native_CM_mutation_calls'] == 0 and len(preflight['native_refusals']) == 3
assert preflight['before'] == preflight['after']
refusal = J('native-cycle.json')
assert refusal['disable_refusal_CR'] == 40 and refusal['unchanged_started_node']
assert not refusal['disableable_flag_present'] and refusal['enable_not_attempted']
disabled = refusal['disable_response']['result']
assert disabled['before'] == disabled['after'] and disabled['CR'] == 40 and disabled['flags'] == 4
assert disabled['before']['status'] & 8 and not disabled['before']['status'] & 0x2000
assert not disabled['api_reported_success'] and not disabled['verified']
restart = J('native-restart.json')
assert restart['phase'] == 'native_exact_instance_restart_and_post_restart_resources_retained'
assert restart['instance'] == r'ACPI\OPEN0063\0' and restart['flags'] == []
assert not restart['reboot_or_force_requested'] and restart['callback_trace_audit_now_passed']
assert restart['before'] == restart['after']
receipt = restart['restart_response']
assert receipt['status'] == 'ok' and receipt['exit_code'] == 0 and receipt['session'] == boots[0]['session']
assert receipt['duration_ms'] == 93 and 'Device restarted successfully.' in receipt['output']
assert restart['pnputil_sha256'] == 'f5f02d90f373243a376f90531d28039b5e9d81b27db010a9620a95ad0ccff52d'

raw = (E / 'native-G63-resources.bin').read_bytes()
audit = J('native-lifecycle-audit.json')
assert len(raw) == 608 and hashlib.sha256(raw).hexdigest() == audit['post_restart_report_sha256'] == restart['after_resource_sha256'] == '40268d597c91d667f6c888121d592573efd362540a1147a90a6cca18f23eb5b7'
u = lambda offset: struct.unpack_from('<I', raw, offset)[0]
assert (u(0), u(4), raw[8:16]) == (608, 1, b'OPG63RS1')
assert [u(i) for i in range(16, 96, 4)] == [26100, 8, 0, 730, 1, 0, 1, 0, 1, 0, 1, 1, 2, 2, 20, 8, 2, 2, 0, 0]
for name, offset, wanted in [('raw', 96, (389, 0, 389, 0xffffffff)),
                              ('translated', 352, (10, 0, 2560, 255))]:
    mem, irq = raw[offset:offset+32], raw[offset+32:offset+64]
    assert mem[:4] == bytes([3, 1, 0, 0]) and irq[:4] == bytes([2, 1, 0, 0])
    assert struct.unpack_from('<QI', mem, 4) == (0xa90000, 0x4000)
    assert struct.unpack_from('<HHIQ', irq, 4) == wanted
    assert mem[20:] == irq[20:] == bytes(12) and raw[offset+64:offset+256] == bytes(192)
    assert audit['post_restart_resources'][name]['vector'] == wanted[2]
trace = E / 'native-lifecycle-trace.txt'
provenance = J('native-trace-provenance.json')
assert sha(trace) == provenance['excerpt_sha256']
assert provenance['source_log_sha256'] == audit['trace_sha256']
events = decode_trace(trace.read_text())
assert events == audit['events'] and audit['passed'] and audit['trace_rejection_cases'] == 3
assert audit['native_restart_and_resource_lifecycle_qualified'] and audit['counter_reset_observed']
assert not audit['context_identity_inferred_from_reused_address']
assert not audit['hardware_MMIO_IRQ_DMA_or_power_vote_qualified']

code = (E / 'own-callback-code.bin').read_bytes()
plan = J('callback-plan.json')
observed = J('callback-debugger-observation.json')
assert len(code) == plan['native_code_bytes'] == observed['native_code_bytes'] == 1424
assert hashlib.sha256(code).hexdigest() == plan['native_code_sha256'] == observed['native_code_sha256'] == '1a7168de99cbd9875e6c2243d3ba265eecf4b26c779d5d3e47309f2d7fbe3575'
assert observed['five_deferred_probes_verified'] and observed['native_CM_mutation_calls'] == 0
assert len(plan['probes']) == 5 and len(plan['REA_evidence_ids']) == 4
instructions = J('REA-own-callback-instructions.json')
assert instructions['target_sha256'] == plan['driver_sha256'] == '52515537783623532bf0fe202f7992a3e2d09242939a86b4233fdca214b83574'
all_instructions = [line for c in instructions['callbacks'] for line in c['result']['instructions']]
assert len(all_instructions) == 356
for index, line in enumerate(all_instructions):
    assert int(line.split(':', 1)[0], 16) == 0x140001000 + index * 4
for probe in plan['probes']:
    offset = int(probe['RVA'], 16) - 0x1000
    assert struct.unpack_from('<I', code, offset)[0] == int(probe['instruction_word'], 16)
    assert probe['REA_instruction'] in all_instructions
cleanup = J('cleanup-verification.json')
assert cleanup['phase'] == 'all_five_probes_removed_exact_callback_code_restored_target_resumed'
assert cleanup['breakpoints_remaining'] == 0 and cleanup['restored_native_code_bytes'] == 1424
assert cleanup['restored_native_code_sha256'] == hashlib.sha256(code).hexdigest()
commands = J('debugger-command-sources.json')['files']
assert [c['name'] for c in commands] == ['G66-first-attach.txt', 'G66-callbacks-v2.txt', 'G66-cleanup.txt']
for command in commands:
    assert hashlib.sha256(command['ASCII_source'].encode('ascii')).hexdigest() == command['sha256']
assert ' and ' in commands[1]['ASCII_source'] and ' && ' not in commands[1]['ASCII_source']
for index in range(5):
    assert 'bc ' + str(index) + '\r\n' in commands[2]['ASCII_source']

recorder = J('native-recorder.json')
assert recorder['certificate_scope'] == 'RAM-only phone session' and not recorder['host_trust_changed']
assert recorder['bind_result']['result']['result']['bound']
package = json.loads((E.parent / 'G63/package-manifest.json').read_text())
for name, digest in package['files'].items():
    assert recorder['hash_qualified_staged_files'][name] == digest
assert recorder['hash_qualified_staged_files']['package.json'] == sha(E.parent / 'G63/package-manifest.json')
returned = J('native-returned-files.json')
assert returned['session'] == boots[1]['session'] and returned['original_software_stack_verified']
assert returned['RAM_recorder_service_absent_after_return'] and returned['final_health']['cpus'] == 8
absence = returned['RAM_recorder_absence_receipt']
assert absence['status'] == 'error' and absence['exit_code'] == 1
assert 'The system was unable to find the specified registry key or value.' in absence['output']
assert returned['software_audit'] == json.loads((E.parent / 'G64/native-recovered-files.json').read_text())['software_audit']
for name, digest in [('boot_a', 'f52c793d01d73eb773bc2f442cdf6eefcd6b7ee395e3af290c8147fefd8caa8e'),
                     ('boot_b', '07dba7ac86e02ea0ff628250991d638da09b8e0680886aee1933df8f56bc4d3b')]:
    assert returned[name]['sha256'] == digest and returned[name]['bytes'] == 201326592 and returned[name]['raw_writes'] == 0
assert returned['G18-maintenance']['sha256'] == '1db2c5d735281ddcb11f1723bb729753e81a74793a495a83c0bece2ffd26d7e9'
assert returned['inactive-G63']['sha256'] == activation['candidate_WIM_sha256'] == 'cbde3b27ab321d054d463e6ebf1c803dea6bb00b3b09419b9c6b8afdeda6aed7'
assert returned['Ntfs_native_file_sha256'] == 'ff70d93b72513a850c86d914aeebedbaf8abf1d9cd26ece81f16cedc5dfbc11a'
checkpoint = J('checkpoint.json')
assert checkpoint['passed'] and checkpoint['all21_goal_areas_active'] and checkpoint['physical_tests_requested'] == 0
assert checkpoint['WIM_firmware_boot_image_or_GPT_writes'] == 0
if (E / 'manifest.json').exists():
    for entry in J('manifest.json')['files']:
        path = ROOT / entry['path']
        assert path.stat().st_size == entry['bytes'] and sha(path) == entry['sha256'], entry['path']
report = {
    'passed': True, 'source_and_bounded_native_evidence_consistent': True,
    'actual_callback_sequence_and_608byte_packet_independently_decoded': True,
    'live_callback_code_matches_static_REA_probe_locations': True,
    'native_restart_and_resource_lifecycle_qualified': True,
    'all_five_probes_removed_and_original_G17_return_verified': True,
    'software_enable_or_hardware_MMIO_IRQ_DMA_power_vote_qualified': False,
    'all21_goal_areas_active': True,
    'scope': 'Read-only public evidence audit; private full-image comparisons and native operations are not rerun.'}
if args.output:
    args.output.write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report))
