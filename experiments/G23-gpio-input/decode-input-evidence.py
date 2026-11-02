"""Audit complete tagged WinDbg captures and the matching native job receipts.

Ignore command echoes and reject nested/incomplete callback captures. This
specifically keeps the first malformed tracing command from becoming proof
of a successful connection. Its corrected manual capture remains separate.
"""
from pathlib import Path
import argparse, hashlib, json, re, struct

W = Path(__file__).resolve().parent
cli = argparse.ArgumentParser()
cli.add_argument('log', type=Path)
cli.add_argument('--verify-existing', action='store_true')
args = cli.parse_args()
text = args.log.read_text(errors='replace')

def blocks(tag, reject_nested=True):
    result = []
    for start in re.finditer(r'^' + re.escape(tag) + r'_BEGIN\s*\n', text, re.M):
        end = re.search(r'^' + re.escape(tag) + r'_END\s*$', text[start.end():], re.M)
        if not end:
            continue
        body = text[start.end():start.end() + end.start()]
        if reject_nested and re.search(r'^G23_\w+_BEGIN\s*$', body, re.M):
            continue
        result.append(body)
    return result

def memory(body):
    data, rows = {}, []
    for line in body.splitlines():
        match = re.match(r'^([0-9a-f]{8}`[0-9a-f]{8})  (.+)', line)
        if not match:
            continue
        address = int(match[1].replace('`', ''), 16)
        tokens = match[2].split('  ')[0].replace('-', ' ').split()
        if not tokens or not all(re.fullmatch('[0-9a-f]{2}', token) for token in tokens):
            continue
        rows.append(address)
        for index, token in enumerate(tokens):
            assert address + index not in data
            data[address + index] = int(token, 16)
    return data, rows

def read(mem, address, count):
    return bytes(mem[address + index] for index in range(count))

def pin_word(body, address):
    pattern = r'^' + re.escape('%08x`%08x' % (address >> 32, address & 0xffffffff))
    values = re.findall(pattern + r'\s+([0-9a-f]{4})\s*$', body, re.M)
    assert len(values) == 1, (hex(address), values)
    return int(values[0], 16)

reads = []
for tag, expected in [('G23_READ_VALUE', 12), ('G23_POST_READ_VALUE', 4)]:
    captured = blocks(tag)
    assert len(captured) == expected, (tag, len(captured))
    for body in captured:
        mem, rows = memory(body)
        params = read(mem, rows[0], 32)
        bank = struct.unpack_from('<H', params)[0]
        pin_pointer = struct.unpack_from('<Q', params, 8)[0]
        count = struct.unpack_from('<I', params, 0x10)[0]
        output = struct.unpack_from('<Q', params, 0x18)[0]
        assert count == 1
        local_pin = pin_word(body, pin_pointer)
        physical = bank * 64 + local_pin
        assert physical in (25, 174) and mem[output] == 0
        reads.append({'tag': tag, 'bank': bank, 'local_pin': local_pin,
                      'physical_pin': physical, 'input_value': mem[output]})
    for pin in (25, 174):
        assert sum(row['physical_pin'] == pin for row in reads if row['tag'] == tag) == expected // 2

contract = json.loads((W.parent / 'gpio-G21/controller-table-candidate.json').read_text())
connections = []
for tag, expected in [('G23_CONNECT_INITIAL', 1), ('G23_CONNECT', 1), ('G23_POST_CONNECT', 2)]:
    captured = blocks(tag)
    assert len(captured) == expected, (tag, len(captured))
    for body in captured:
        registers = {name: int(value, 16) for name, value in re.findall(r'^(x[01])=([0-9a-f]+)\s*$', body, re.M)}
        assert registers.keys() == {'x0', 'x1'}
        mem, _ = memory(body)
        params = read(mem, registers['x1'], 48)
        bank = struct.unpack_from('<H', params)[0]
        count = struct.unpack_from('<H', params, 0x10)[0]
        mode = struct.unpack_from('<I', params, 0x14)[0]
        pin = pin_word(body, struct.unpack_from('<Q', params, 8)[0]) + 64 * bank
        assert pin in (25, 174) and count == mode == 1
        assert params[0x18] == 0 and struct.unpack_from('<H', params, 0x1c)[0] == 0
        assert struct.unpack_from('<QI', params, 0x20) == (0, 0)
        row = {'tag': tag, 'physical_pin': pin, 'connect_mode_input': True,
               'pull_configuration': 0, 'drive_strength_request': 0,
               'vendor_data_length': 0, 'context': hex(registers['x0'])}
        if tag == 'G23_POST_CONNECT':
            ctx = read(mem, registers['x0'], 232)
            for field in contract['selector4_values']:
                assert struct.unpack_from('<I', ctx, int(field['context_offset'], 16))[0] == field['value']
            assert struct.unpack_from('<III', ctx, 0x14) == (384, 210, 0)
            assert struct.unpack_from('<I', ctx, 0x24)[0] == 4096
            assert struct.unpack_from('<Q', ctx, 8)[0] and struct.unpack_from('<Q', ctx, 0x30)[0]
            assert struct.unpack_from('<Q', ctx, 0xe0)[0]
            row.update(all_38_reinitialized_values_match=True, WDF_owner_and_pin_buffer_nonzero=True)
        connections.append(row)

for tag in ('G23_UNEXPECTED_WRITE', 'G23_UNEXPECTED_POST_WRITE'):
    assert not re.search(r'^' + tag + r'\s*$', text, re.M)
initial = json.loads((W / 'native-live-code.json').read_text())
boot = json.loads((W / 'boot-canary.json').read_text())
sid = boot['session']
assert initial['session'] == sid
first_live = blocks('G23_AFTER1')
assert len(first_live) == 1
live_mem, _ = memory(first_live[0])
image_base = int(initial['module_base'], 16)
fix = json.loads((W.parent / 'gpio-G22/private/G22-qcgpio-development.json').read_text())
assert fix['output_sha256'] == '4df56f98b47a988a491e14501547b6da98b277a01881deffdf1b4ca315e178b3'
for region in fix['regions'][:3]:
    assert read(live_mem, image_base + int(region['rva'], 16), region['length']) == bytes.fromhex(region['after'])
assert re.search(r'^fffff800`2a01d848\s+000000e8$', first_live[0], re.M)
initial_context = read(live_mem, int(initial['controller_context_address'], 16), 232)
for field in contract['selector4_values']:
    assert struct.unpack_from('<I', initial_context, int(field['context_offset'], 16))[0] == field['value']
assert struct.unpack_from('<Q', initial_context, 0xe0)[0]
for index in range(1, 5):
    result = json.loads((W / ('native-rescan-%d.json' % index)).read_text())
    assert result['phase'] == 'native_PnP_rescan_completed_control_healthy' and result['session'] == sid
    assert result['probe']['detail']['cpus'] == 8
restart = json.loads((W / 'native-restart-1.json').read_text())
assert restart['phase'] == 'restart_completed_same_session_GPIO_started' and restart['session'] == sid
assert 'Device restarted successfully.' in restart['restart']['output']
restarted = json.loads((W / 'post-restart-module.json').read_text())
assert restarted['namespace']['GRCT'] == 3 and restarted['namespace']['GQCT'] == restarted['namespace']['GPCT'] == 10
final = blocks('G23_FINAL')
assert len(final) == 1
f = final[0]
values = {key: int(value, 16) for key, value in re.findall(r'Integer\((\w+):Value=0x([0-9a-f]+)\[', f)}
assert values['GRDY'] == 1 and values['GRCT'] == 3 and values['RCNT'] == 16
assert values['R025'] == values['R174'] == 0 and values['GQCT'] == values['GPCT'] == 10
assert '# f119000 00000000 00000000 000000e2 00000000' in f
assert '# f1ae000 00001800 00000000 000000e2 00000000' in f
assert not re.search(r'^\s+\d+ e ', f, re.M)
result = {'phase': 'native_GPIO_input_and_restart_reconnection_verified', 'session': sid,
          'reads': reads, 'completed_read_callbacks': len(reads), 'connections': connections,
          'physical_pins': [25, 174], 'input_reads_per_pin': 8,
          'instrumented_write_callback_hits': 0,
          'native_restart_ms': restart['restart']['duration_ms'],
          'controller_module_relocated': initial['module_base'] != restarted['module_base'],
          'current_module_base': restarted['module_base'], 'final_namespace': values,
          'all_breakpoints_cleared': True,
          'tracing_syntax_error_recovered_without_job_replay': 'Syntax error' in text,
          'source_log': str(args.log), 'source_log_sha256': hashlib.sha256(args.log.read_bytes()).hexdigest(),
          'limits': ['Digital input snapshots; no analog rail or controller-identity measurement.',
                     'No output-latch write requested; input connections do configure pull/OE/EGPIO.',
                     'Zero output-callback hits applies to instrumented scan windows, not the uninstrumented restart.',
                     'No actual hardware interrupt, SPI/touch transaction, or wake qualification.',
                     'Uses the unchanged unsigned G22 development fix and connected kernel debugger.']}
out = W / 'native-input-result.json'
if args.verify_existing:
    assert json.loads(out.read_text()) == result
else:
    assert not out.exists()
    out.write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps({key: result[key] for key in ['phase', 'session', 'completed_read_callbacks',
      'input_reads_per_pin', 'native_restart_ms', 'controller_module_relocated', 'all_breakpoints_cleared']}, indent=2))
