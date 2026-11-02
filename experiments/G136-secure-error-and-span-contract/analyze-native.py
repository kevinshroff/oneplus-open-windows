"""Cross-bind the four G136 tables without promoting models to hardware facts."""
from pathlib import Path
import base64
import hashlib
import json
import re
import struct

w = Path(__file__).resolve().parent
p = w / 'private'
load = lambda n: json.loads((p / n).read_text())
d = load('DSP-native.json')
m = load('OPAS-native.json')
a = load('raw-OAPF-native.json')
assert d['ok'], 'Decode retained raw tables before interpreting a refused reader.'
r = d['report']
s = r['SCM_error']
meta = m.get('report', {})
hashes = {}
for signature, encoded, expected in [
        ('OADP', r['raw_table_base64'], r['table_sha256']),
        ('OSER', s['raw_table_base64'], s['table_sha256']),
        ('OPAS', m['raw_table_base64'], meta['table_sha256']),
        ('OAPF', a['raw_base64'], a['sha256'])]:
    raw = (p / ('native-' + signature + '.bin')).read_bytes()
    assert raw == base64.b64decode(encoded, validate=True)
    hashes[signature] = hashlib.sha256(raw).hexdigest()
    assert hashes[signature] == expected
    assert raw[:4] == signature.encode() and len(raw) == struct.unpack_from('<I', raw, 4)[0] and sum(raw) % 256 == 0
assert a['ok'] and a['stable_double_read'] and r['stable_double_read'] and s['stable_double_read']
raw = (p / 'native-OAPF.bin').read_bytes()
assert raw[16:24] == b'G119PFLT'
text = raw[36:].replace(b'\r\n', b'\n')
assert all(c == 10 or 32 <= c <= 126 for c in text)
text = text.decode('ascii')
assert text.startswith('OPEN-ADSP-PREFLIGHT G136 version=1\ninput_sha256=ba26f22b2ee03897148adaa7f34e1df350ef7f26bd24af6dbcd5878e8020e882\n')
assert 'DSP_start=memory_error_diagnostic source_writes=blocked\n' in text
suffix = re.findall(r'^DSP_start=memory_error_diagnostic PIL_request_count=([01])$', text, re.M)
assert len(suffix) == 1 and int(suffix[0]) == r['PIL_requests']
final = re.findall(r'^FINAL file_status=(.*?) memory_status=(.*?) cleanup_status=(.*?) truncated=([01])$', text, re.M)
assert len(final) == 1 and final[0][3] == '0'
files = re.findall(r'^file ([0-9]+) ([a-z0-9_.]+) bytes=([0-9]+) read=([0-9]+) status=(.*?)$', text, re.M)
files_ok = len(files) == 64 and all(int(row[0]) == i and row[2] == row[3] and row[4] in ['0', 'Success'] for i, row in enumerate(files))
cross = False
if m.get('ok') and meta.get('PIL_code_verified') and meta.get('SCM_code_verified'):
    if int(r['SCM_slot'], 16):
        image = int(meta['SCM_image_base'], 16)
        assert int(r['SCM_slot'], 16) == image + int(meta['SCM_table_RVA'], 16) + 56
        assert int(r['original_method'], 16) == image + int(meta['SCM_function_RVA'], 16)
        assert int(s['SCM_image_base'], 16) == image and int(s['cache_slot'], 16) == image + 0xe580
        cross = True
if r['PAS_entered_stages']:
    assert cross and files_ok and meta['preflight_ready']
    assert r['auth_entered_mask'] == r['auth_accepted_mask'] == 0
    assert r['PAS_entered_stages'] <= 2 and r['PAS_returned_stages'] <= 2
policy = re.findall(r'^G134_inventory_policy matched=([01]) CPU_permissions=not_queried DMA_ownership=not_proved$', text, re.M)
assert len(policy) == 1
secure = [{'command': hex(v['command']), 'signed_low32': v['TzStatus_signed32'],
           'low32_hex': '0x%08x' % v['TzStatus32'], 'PAS_record_index': v['PAS_record_index'],
           'API_status': v['original_API_status'], 'API_result0': v['original_API_result0'],
           'OEM_mapping_consistent': v['OEM_mapping_consistent']} for v in s['records']]
result = {'native_G136_firmware_boots': 1, 'report_valid': True, 'raw_table_sha256': hashes,
          'source_file_rows': len(files), 'source_file_rows_complete': files_ok,
          'file_memory_cleanup_status': final[0][:3], 'inventory_policy_matched': policy[0] == '1',
          'SCM_cross_bound_to_OPAS': cross,
          'final_status': r['final_status'], 'raw_status': r['raw_status'], 'flags': r['flags'],
          'PIL_requests': r['PIL_requests'], 'PAS_entered_stages': r['PAS_entered_stages'],
          'PAS_returned_stages': r['PAS_returned_stages'], 'phase': r['phase'], 'fault': r['fault'],
          'memory_setup_accepted': r['memory_setup_accepted'], 'diagnostic_stop': r['diagnostic_stop'],
          'auth_entered_mask': r['auth_entered_mask'], 'auth_accepted_mask': r['auth_accepted_mask'],
          'SCM_method_stores': r['hook_stores'], 'serial_cache_stores': s['hook_stores'],
          'SCM_fatal_restore': r['fatal_restore'], 'serial_fatal_restore': s['fatal_restore'],
          'serial_restoration': s['restore_status'], 'secure_error32_cross_bound': s['secure_error32_cross_bound'],
          'secure_errors': secure, 'serial_parser_fault': s['parser_fault'],
          'serial_rejected': s['rejected'], 'serial_ignored': s['ignored'],
          'full64_SMC_X0_qualified': False, 'DSP_running_qualified': False,
          'GLINK_ready_qualified': False, 'charging_qualified': False, 'partition_flashes': 0,
          'scope': 'Native diagnostic reports and explicit partial state; no same-boot retry, AUTH, shutdown or main request.'}
(p / 'native-analysis.json').write_text(json.dumps(result, indent=2) + '\n')
(p / 'native-preflight.txt').write_text(text)
print(json.dumps(result, indent=2))
