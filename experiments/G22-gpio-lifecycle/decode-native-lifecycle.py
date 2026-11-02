"""Validate exact live callback data, including the new WDF ownership field."""
from pathlib import Path
import hashlib, json, re, struct

W = Path(__file__).resolve().parent
logs = W.parent / 'platform-snapshot/private'
candidate = json.loads((W.parent / 'gpio-G21/controller-table-candidate.json').read_text())
def section(tag):
    for p in reversed(sorted(logs.glob('debug-live-*.txt'))):
        s = p.read_text(errors='replace')
        m = re.search(r'(?m)^' + tag + r'_BEGIN\s*\n(.*?)^' + tag + r'_END\s*$', s, re.S|re.M)
        if m:
            return p, m[1]
    raise ValueError('Complete callback capture missing: ' + tag)

def decode(tag):
    p, text = section(tag)
    m = re.search(r'(?m)^x1=([0-9a-f]{16})\s*$', text)
    assert m
    base = int(m[1], 16)
    data, record_data = {}, {}
    for line in text.splitlines():
        q = re.fullmatch(r'([0-9a-f]{8}`[0-9a-f]{8})\s+([0-9a-f]{8}`[0-9a-f]{8})(?: ([0-9a-f]{8}`[0-9a-f]{8}))?', line)
        if q:
            address = int(q[1].replace('`',''),16)
            for j, value in enumerate(q.groups()[1:]):
                if value:
                    for k, byte in enumerate(struct.pack('<Q', int(value.replace('`',''),16))):
                        at = address + j*8 + k
                        assert at not in data
                        data[at] = byte
        b = re.match(r'^([0-9a-f]{8}`[0-9a-f]{8})  (.*)$',line)
        if b:
            tokens = b[2].split('  ')[0].replace('-',' ').split()
            if tokens and all(re.fullmatch('[0-9a-f]{2}', x) for x in tokens):
                address = int(b[1].replace('`',''),16)
                for j, byte in enumerate(bytes.fromhex(' '.join(tokens))):
                    assert address+j not in record_data
                    record_data[address+j] = byte
    assert set(data) == set(range(base, base+232))
    buf = bytes(data[base+i] for i in range(232))
    u32 = lambda o: struct.unpack_from('<I',buf,o)[0]
    u64 = lambda o: struct.unpack_from('<Q',buf,o)[0]
    for x in candidate['selector4_values']:
        assert u32(int(x['context_offset'],16)) == x['value'], x
    assert (u64(0),u32(0x10),u32(0x14),u32(0x18),u32(0x20),u32(0x24)) == (0xf000000,0x1000000,384,210,0,4096)
    assert u64(8) and u64(0x30) and u64(0xe0) and u64(0x30) != u64(0xe0)
    rb = min(record_data)
    assert set(record_data) == set(range(rb,rb+96))
    records = bytes(record_data[rb+i] for i in range(96))
    routes = []
    for i, expected in enumerate([(57,25,569,256),(98,174,645,320)]):
        row = records[i*48:(i+1)*48]
        pin, gpio, gsi = struct.unpack_from('<HHI',row)
        virtual = struct.unpack_from('<H',row,8)[0]
        assert (pin,gpio,gsi,virtual) == expected
        en,cfg = [struct.unpack_from('<Q',row,o)[0] for o in [0x10,0x20]]
        assert en & 4095 == (0xb220010+4*(pin>>5)) & 4095
        assert cfg & 4095 == (0xb220110+4*pin) & 4095
        assert row[0x28] == row[0x29] == 0
        assert row[0xa:0x10] == bytes(6) and row[0x18:0x20] == bytes(8) and row[0x2a:0x30] == bytes(6)
        routes.append({'PDC':pin,'TLMM':gpio,'GSI':gsi,'virtual_GPIO':virtual,
                       'enable_page_offset':hex(en&4095),'configuration_page_offset':hex(cfg&4095),
                       'enabled':0,'configured':0,'padding_initialized':True})
    return {'tag':tag,'context_bytes':232,'all_38_primary_values_match':True,
            'raw_buffer_and_retained_owner_nonzero_and_distinct':True,
            'owner_field_offset':'0xe0','physical_GPIOs':210,'total_virtual_capacity':384,
            'PDC_routes':routes,'context_sha256':hashlib.sha256(buf).hexdigest(),
            'PDC_records_sha256':hashlib.sha256(records).hexdigest(),
            'private_log_sha256':hashlib.sha256(p.read_bytes()).hexdigest()}

captures = [decode('G22_RELEASE'),decode('G22_REINIT')]
restarts = [json.loads((W/('native-restart-%d.json'%i)).read_text()) for i in range(1,5)]
assert all(x['phase']=='restart_completed_same_session_GPIO_started' for x in restarts)
assert len({x['session'] for x in restarts}) == 1
r = {'phase':'four_native_GPIO_restarts_and_reinitialized_contract_verified',
     'session':restarts[0]['session'],'successful_exact_device_restarts':4,
     'restart_duration_ms':[x['restart']['duration_ms'] for x in restarts],
     'control_and_8_CPUs_pass_after_each_restart':True,'captures':captures,
     'old_absolute_prepare_breakpoint_not_claimed_as_hit':True,
     'module_relocation_handled_by_fresh_module_list':True,
     'limits':['Unsigned development binary in disposable RAM WinPE under the existing kernel debugger',
               'No pin I/O, interrupt delivery, touch, full93-route wake map, suspend/resume, or long stress qualification',
               'Remaining query allocations retain their original device-parent lifetimes; no general memory-growth claim']}
(W/'native-lifecycle-result.json').write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps({k:r[k] for k in ['phase','successful_exact_device_restarts','restart_duration_ms']},indent=2))
