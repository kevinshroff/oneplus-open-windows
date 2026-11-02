"""Check project trace cleanup and original G17 control after the client tests."""
from pathlib import Path
import json
from relay import Relay
W=Path(__file__).resolve().parent;R=Relay('final-state.json');s=R.s
native=json.loads((W/'normal-G17-refusal-v4.json').read_text());assert native['phase']=='small_native_client_refuses_original_G17_before_project_interface_file_or_IOCTL_operations'and native['audit_before']==native['audit_after']
assert json.loads((W/'same-path-header-comparison.json').read_text())['original_project_client_bytes_restored']
reg=r'X:\Windows\System32\reg.exe'
for label,key in [('clock-service-absent',r'HKLM\SYSTEM\CurrentControlSet\Services\OpenG67'),('project-IFEO-absent',r'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\G67-client-v3.exe')]:
 r=R.op(label,'phone','exec',argv=[reg,'query',key]);assert r['status']=='error'and r['exit_code']==1 and 'unable to find'in r['output'];s[label]=True;R.persist()
r=R.op('final-health','phone','probe');assert r['status']=='ok'and r['detail']['arch']=='arm64'and r['detail']['cpus']==8
s.update(phase='original_G17_stack_and_control_preserved_project_trace_key_and_clock_service_absent',session=r['session'],health={k:r['detail'][k]for k in ['os','arch','cpus','version','system_root']},original_software_audit=native['audit_after'],firmware_WIM_FAT_BCD_GPT_or_boot_image_write=False,new_driver_loaded=False,physical_tests_requested=0,fresh_full_protected_partition_hash_audit_claimed=False,all21_goal_areas_active=True);R.persist();print(json.dumps({k:s[k]for k in ['phase','session','new_driver_loaded']}))
