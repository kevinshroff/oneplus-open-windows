"""Cross-bind five tables from the combined G146 boot without promoting models to hardware facts."""
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
i = load('PIL-native.json')
intent=load('G146-boot-intent.json');assert intent['phase']=='temporary_boot_command_accepted'
assert i['ok'] and i['report']['report_valid']
assert not i['report']['memory_eligible'] and not i['report']['DMA_ownership_proved'] and not i['report']['DSP_started']
assert d['ok'], 'Decode retained raw tables before interpreting a refused reader.'
r = d['report']
s = r['SCM_error']
if r['auth_entered_mask']:
    assert r['DTB_admission']['finite_DTB_admission_complete']
    assert r['auth_entered_mask']==1 and r['PAS_entered_stages']==3
if r['PAS_sequence_accepted']:
    assert r['auth_accepted_mask']==1 and r['phase']==[3,0]
    assert len(r['records'])==3 and r['PAS_entered_stages']==r['PAS_returned_stages']==3
    for record in r['records']:
        assert record['OriginalStatus']==0 and record['Results'][0:2]==[1,0]
        assert record['ReturnedStatus']==0 and record['Refusal']==0
    assert r['records'][1]['Arguments']==[36,0x9e980000,0x80000]
    assert r['records'][2]['Arguments']==[36,0,0] and r['records'][2]['Param']==1
    assert s['record_count']==0 and not(s.get('records')or[])
meta = m.get('report', {})
hashes = {}
for signature, encoded, expected in [
        ('OADP', r['raw_table_base64'], r['table_sha256']),
        ('OSER', s['raw_table_base64'], s['table_sha256']),
        ('OPAS', m.get('raw_table_base64') or meta['raw_table_base64'], meta['table_sha256']),
        ('OAPF', a['raw_base64'], a['sha256']),
        ('OPIL', i['raw_table_base64'], i['raw_sha256'])]:
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
assert text.startswith('OPEN-ADSP-PREFLIGHT G146 version=1\ninput_sha256=ba26f22b2ee03897148adaa7f34e1df350ef7f26bd24af6dbcd5878e8020e882\n')
assert 'DSP_start=dtb_auth_diagnostic source_writes=blocked\n' in text
suffix = re.findall(r'^DSP_start=dtb_auth_diagnostic PIL_request_count=([01])$', text, re.M)
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
    assert 'G144_setup_footprint ready=1 scope=memory_setup_only' in i['report']['text']
    assert 'G146_DTB_request base=9E980000 bytes=80000 payload_bytes=8376 payload_AT_tag=44 hook_AT_tag=FF main=blocked' in text
    assert cross and files_ok and meta['preflight_ready']
    assert r['auth_entered_mask']<=1 and r['auth_accepted_mask']<=1
    assert r['PAS_entered_stages']<=3 and r['PAS_returned_stages']<=3
dtb_return=re.findall(r'^G146_DTB_return loaded=([01]) public_status=([0-9a-fA-F]+) AUTH_entered=([01]) AUTH_accepted=([01]) stop_before_main=([01]) copy=([01]) hash_matched=([01]) PRE_POST_direct=not_observed$',text,re.M)
assert len(dtb_return)==1
v=dtb_return[0]
assert [int(v[k])for k in [0,2,3,4,5,6]]==[int(r['DTB_public_success']),r['auth_entered_mask'],r['auth_accepted_mask'],int(r['stop_before_main']),int(r['DTB_admission']['copy_granted']),int(r['DTB_admission']['payload_matched'])]
assert int(v[1],16)==int(r['raw_status']['DTB_PIL'],16)
checks=re.findall(r'^G146_DTB_check index=([012]) status=(.*?) reason=([0-9a-fA-F]+) CPU_pages=([0-3]) AT=([0-9]+) MMIO=([0-9]+) Demura=([0-9a-fA-F]+)/([0-9a-fA-F]+) complete=([01]) global_DMA=not_proved$',text,re.M)
assert len(checks)==int(r['DTB_admission']['copy_attempts'])+int(r['DTB_admission']['payload_attempts'] and r['DTB_admission']['copy_granted'])+int(r['DTB_admission']['payload_matched'])
for row in checks:
    c=r['DTB_admission']['checks'][int(row[0])]
    assert [int(row[k],16)for k in [2,6,7]]==[c['reason'],*c['Demura_words']]
    assert [int(row[k])for k in [3,4,5,8]]==[c['CPU_pages'],c['AT_queries'],c['MMIO_reads'],int(c['complete'])]
    if c['complete']:assert row[1]=='Success'
policy = re.findall(r'^G134_inventory_policy matched=([01]) CPU_permissions=not_queried DMA_ownership=not_proved$', text, re.M)
assert len(policy) == 1
secure = [{'command': hex(v['command']), 'signed_low32': v['TzStatus_signed32'],
           'low32_hex': '0x%08x' % v['TzStatus32'], 'PAS_record_index': v['PAS_record_index'],
           'API_status': v['original_API_status'], 'API_result0': v['original_API_result0'],
           'OEM_mapping_consistent': v['OEM_mapping_consistent']} for v in (s.get('records') or [])]
result = {'native_G146_firmware_boots': 1, 'report_valid': True, 'raw_table_sha256': hashes,
          'source_file_rows': len(files), 'source_file_rows_complete': files_ok,
          'file_memory_cleanup_status': final[0][:3], 'inventory_policy_matched': policy[0] == '1',
          'SCM_cross_bound_to_OPAS': cross,
          'final_status': r['final_status'], 'raw_status': r['raw_status'], 'flags': r['flags'],
          'PIL_requests': r['PIL_requests'], 'PAS_entered_stages': r['PAS_entered_stages'],
          'PAS_returned_stages': r['PAS_returned_stages'], 'phase': r['phase'], 'fault': r['fault'],
          'PAS_records': r['records'], 'PAS_sequence_accepted': r['PAS_sequence_accepted'],
          'memory_setup_accepted': r['memory_setup_accepted'], 'diagnostic_stop': r['diagnostic_stop'],
          'DTB_admission':r['DTB_admission'],'DTB_public_success':r['DTB_public_success'],'DTB_load_returned':r['DTB_load_returned'],'stop_before_main':r['stop_before_main'],'PRE_POST_directly_observed':False,'global_DMA_ownership_qualified':False,
          'auth_entered_mask': r['auth_entered_mask'], 'auth_accepted_mask': r['auth_accepted_mask'],
          'SCM_method_stores': r['hook_stores'], 'serial_cache_stores': s['hook_stores'],
          'SCM_fatal_restore': r['fatal_restore'], 'serial_fatal_restore': s['fatal_restore'],
          'serial_restoration': s['restore_status'], 'secure_error32_cross_bound': s['secure_error32_cross_bound'],
          'secure_errors': secure, 'serial_parser_fault': s['parser_fault'],
          'serial_rejected': s['rejected'], 'serial_ignored': s['ignored'],
          'full64_SMC_X0_qualified': False, 'DSP_running_qualified': False,
          'GLINK_ready_qualified': False, 'charging_qualified': False, 'partition_flashes': 0,
          'PIL_inventory': i['report'],
          'PIL_policy_source': 'G138 shipped A/B devcfg; live secure globals not captured',
          'PIL_inside_request_entered': r['PAS_entered_stages'] >= 2,
          'source_image_sha256': intent['image_sha256'],
          'scope': 'Native G146 DTB-only diagnostic; original INIT/MEM_SETUP, separately admitted8376-byte copy/hash, DTB AUTH and unchanged original POST branch. Main blocked; no partition flash, remapping, shutdown or same-boot retry. PRE/POST return values not directly observed; no global DMA or production power lease qualification.'}
(p / 'native-analysis.json').write_text(json.dumps(result, indent=2) + '\n')
(p / 'native-preflight.txt').write_text(text)
print(json.dumps({k:v for k,v in result.items()if k not in ['PAS_records','PIL_inventory','DTB_admission']}, indent=2))
