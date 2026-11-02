"""Verify G23's initial live G22 repair and save its restart prerequisite."""
from pathlib import Path
import argparse, hashlib, json, re, struct

W = Path(__file__).resolve().parent
cli = argparse.ArgumentParser()
cli.add_argument('log', type=Path)
cli.add_argument('--verify-existing', action='store_true')
args = cli.parse_args()
source = args.log.read_text(errors='replace')
match = re.search(r'^G23_AFTER1_BEGIN\n(.*?)^G23_AFTER1_END$', source, re.M | re.S)
assert match
body, mem = match[1], {}
for line in body.splitlines():
    match = re.match(r'^([0-9a-f]{8}`[0-9a-f]{8})  (.+)', line)
    if not match:
        continue
    address = int(match[1].replace('`', ''), 16)
    tokens = match[2].split('  ')[0].replace('-', ' ').split()
    if not tokens or not all(re.fullmatch('[0-9a-f]{2}', token) for token in tokens):
        continue
    for index, token in enumerate(tokens):
        assert address + index not in mem
        mem[address + index] = int(token, 16)
def read(address, count):
    return bytes(mem[address + index] for index in range(count))
base = 0xfffff8002a010000
fix = json.loads((W.parent / 'gpio-G22/private/G22-qcgpio-development.json').read_text())
assert fix['output_sha256'] == '4df56f98b47a988a491e14501547b6da98b277a01881deffdf1b4ca315e178b3'
checks = []
for region in fix['regions'][:3]:
    assert read(base + int(region['rva'], 16), region['length']) == bytes.fromhex(region['after'])
    checks.append({'rva': region['rva'], 'bytes': region['length'], 'exact_match': True})
assert re.search(r'^fffff800`2a01d848\s+000000e8$', body, re.M)
context_address = 0xffffc4861b295810
ctx = read(context_address, 232)
contract = json.loads((W.parent / 'gpio-G21/controller-table-candidate.json').read_text())
values = []
for field in contract['selector4_values']:
    offset = int(field['context_offset'], 16)
    value = struct.unpack_from('<I', ctx, offset)[0]
    assert value == field['value']
    values.append({'context_offset': field['context_offset'], 'value': value})
assert struct.unpack_from('<III', ctx, 0x14) == (384, 210, 0)
assert struct.unpack_from('<I', ctx, 0x24)[0] == 4096
assert struct.unpack_from('<Q', ctx, 8)[0] and struct.unpack_from('<Q', ctx, 0x30)[0]
assert struct.unpack_from('<Q', ctx, 0xe0)[0]
namespace = {key: int(value, 16) for key, value in re.findall(r'Integer\((\w+):Value=0x([0-9a-f]+)\[', body)}
assert namespace == {'GRDY': 1, 'STCT': 15, 'RCNT': 4, 'R025': 0, 'R174': 0}
assert '# f119000 00000000 00000000 000000e2 00000000' in body
assert '# f1ae000 00001800 00000000 000000e2 00000000' in body
result = {'phase': 'native_live_development_code_and_context_size_verified',
          'session': json.loads((W / 'boot-canary.json').read_text())['session'],
          'driver_sha256': fix['output_sha256'], 'module_base': hex(base),
          'live_code_regions': checks, 'registered_context_bytes': 232,
          'controller_context_address': hex(context_address), 'primary_context_values': values,
          'WDF_owner_nonzero': True, 'pin_buffer_nonzero': True, 'TLMM_mapping_nonzero': True,
          'source_log': str(args.log), 'source_log_sha256': hashlib.sha256(args.log.read_bytes()).hexdigest(),
          'native_first_reads': {key: namespace[key] for key in ['GRDY', 'RCNT', 'R025', 'R174']},
          'scope': 'Actual GPIO input connections/reads, not touch protocols, real interrupts or wake support.'}
result['native_first_reads'].update(pin25_control='0x0', pin174_control='0x1800', both_interrupt_config='0xe2')
out = W / 'native-live-code.json'
if args.verify_existing:
    assert json.loads(out.read_text()) == result
else:
    assert not out.exists()
    out.write_text(json.dumps(result, indent=2) + '\n')
print(result['phase'])
