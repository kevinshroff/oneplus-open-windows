#!/usr/bin/env python3
"""Create intentionally inadmissible templates; never infer actual boot facts."""
import argparse
import json
from pathlib import Path

COMMON = ['context', 'current_tables', 'loaded_owner', 'endpoint_BAR0_resource',
          'accepted_boot_receipt', 'normal_boot_admission', 'action_ledger']
POST = ['native_init_selection', 'native_init_outcome', 'failed_scan_log',
        'pre_phase_result', 'pre_phase_marker']

def templates():
    for phase in ('PRE_HOST_INIT', 'POST_STALL'):
        proof = dict(schema='G1295-root-phase-fault-epoch/1', phase=phase,
            action_ledger_file='', boot_id=None, phone_session='', created_utc='', root_nonce='',
            image_sha256='', nt_base='', held_pc='', owner_base='', owner_size=None,
            owner_timestamp=None, owner_checksum=None, BAR0_resource_base='', BAR0_resource_bytes=None,
            root_qualifies_actual_fresh_normal_boot=False,
            root_qualifies_current_endpoint_BAR0_resource=False,
            root_attests_no_root_selected_force_native_diagnostic_reset_or_error_clear_in_selected_interval=False,
            root_owns_break6=False, root_qualifies_current_tables_and_resource_owner=False,
            root_qualifies_fixed_physical_device_ranges_uncached=False,
            actual_evidence_sha256={key: '' for key in COMMON + (['pre_host_init_state'] if phase == 'PRE_HOST_INIT' else POST)})
        ledger = dict(schema='G1295-actual-boot-action-ledger/1', boot_id=None,
            phone_session='', image_sha256='', phase=phase, created_utc='',
            native_init_calls=None, explicit_scan_calls=None, root_force_calls=None,
            root_native_diagnostic_calls=None, root_reset_calls=None, root_status_clear_calls=None,
            wlan_service_start=None, wlan_service_state='',
            root_proves_no_native_init_in_actual_boot=False,
            actual_single_init_outcome_recorded=False, actual_post_init_failure_boundary_recorded=False,
            **{key + '_sha256': '' for key in ['accepted_boot_receipt', 'normal_boot_admission',
                'native_init_selection', 'native_init_outcome', 'failed_scan_log',
                'pre_host_init_state', 'pre_phase_result', 'pre_phase_marker']})
        yield phase + '-proof.template.json', proof
        yield phase + '-ledger.template.json', ledger

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    for name, value in templates():
        (args.out / name).write_text(json.dumps(value, indent=2) + '\n')

if __name__ == '__main__':
    main()
