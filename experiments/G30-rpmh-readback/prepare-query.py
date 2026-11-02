"""Bind one fixed resource READ to a fresh native G30 TCS/IRQ snapshot.

Generates source and provenance only; does not stage or execute native code.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import secrets

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--inputs', type=Path, required=True)
p.add_argument('--baseline', type=Path, required=True)
p.add_argument('--kind', choices=['voltage', 'mode', 'sh1'], required=True)
p.add_argument('--output', type=Path, required=True)
p.add_argument('--nonce', help='Use a saved nonce for offline historical reproduction only')
a = p.parse_args()
W = Path(__file__).resolve().parent
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
old_binding_path = a.inputs / 'rpmh-G29/query-binding.json'
old_binding = json.loads(old_binding_path.read_text())
shadow_path = a.inputs / 'rpmh-G29/shadow-plan.json'
shadow = json.loads(shadow_path.read_text())
platform_path = a.inputs / 'touch-G28/RPMh-platform-binding.json'
platform = json.loads(platform_path.read_text())
db_path = a.inputs / 'touch-G25/cmddb-decoded.json'
db = json.loads(db_path.read_text())
assert sha(db_path) == platform['inputs']['captured_command_DB_decode_sha256']
reg_path = a.inputs / 'touch-G25/private/rpmh-regulator.c'
assert sha(reg_path) == platform['inputs']['regulator_source_sha256']
reg = reg_path.read_text()
assert re.search(r'RPMH_REGULATOR_REG_VRM_MODE\s*= 2,', reg)
assert re.search(r'RPMH_REGULATOR_REG_VRM_VOLTAGE\s*= 0,', reg)
assert 'cmd[j].addr = aggr_vreg->addr + i * 4;' in reg
source_fetch = json.loads((a.inputs / 'rpmh-G29/read-source-fetch.json').read_text())
source_path = a.inputs / 'rpmh-G29/private/read-semantics/rpmh-rsc.c'
assert sha(source_path) == next(f['sha256'] for f in source_fetch['files'] if f['path'].endswith('/rpmh-rsc.c'))
source = source_path.read_text()
assert 'if (!msg->is_read)' in source and 'RSC_DRV_CMD_RESP_DATA' in source
name, delta = {'voltage': ('ldob4', 0), 'mode': ('ldob4', 8), 'sh1': ('SH1', 0)}[a.kind]
entry, = [x for x in db['entries'] if x['id'] == name]
address = int(entry['address'], 16) + delta
assert address == {'voltage': 0x40800, 'mode': 0x40808, 'sh1': 0x50008}[a.kind]
assert entry['slave_id'] == (5 if a.kind == 'sh1' else 4)
baseline = json.loads(a.baseline.read_text())
assert baseline['phone_session'] == old_binding['phone_session']
native = baseline['native_result']
assert native['success'] and native.get('MMIO_writes') == 0 and len(native['reads']) == 17
values = native['values']
assert values.keys() == old_binding['baseline'].keys()
for key in values:
    if key not in ['CMD0_STATUS', 'CMD0_RESP_DATA']:
        assert values[key] == old_binding['baseline'][key], key
nonce = a.nonce if a.nonce is not None else secrets.token_hex(8)
assert re.fullmatch('[0-9a-f]{16}', nonce)
binding = {
    'kind': a.kind, 'nonce': nonce,
    'phone_session': baseline['phone_session'], 'baseline': values,
    'request_address': hex(address), 'request_MSGID': '0x108',
    'request_kind': 'READ: WRITEbit16clear, RESPbit8set, length8',
    'no_supply_or_clock_vote': True, 'resource': name,
    'source_address_basis': {'command_DB_entry': entry, 'delta': delta},
    'native_baseline_sha256': sha(a.baseline)
}
addresses = {k: int(v, 16) for k, v in shadow['fields'].items()}
template_path = W / 'query-template.js'
template = template_path.read_text()
assert template.count('G30_RESOURCE_ADDRESS') == 3
assert '"CMD0_MSGID",0x108,"prepare_READ"' in template
assert '"TCS_CONTROL",0x1010000,"READ_trigger"' in template
script = 'var G30_Q_BINDING=' + json.dumps(binding, separators=(',', ':')) + ';\n'
script += 'var G30_Q_ADDR=' + json.dumps(addresses, separators=(',', ':')) + ';\n'
script += 'var G30_RESOURCE_ADDRESS=' + hex(address) + ';\n' + template
a.output.mkdir(parents=True, exist_ok=False)
out = a.output / ('G30-read-' + a.kind + '.js')
out.write_text(script)
(a.output / 'binding.json').write_text(json.dumps(binding, indent=2) + '\n')
(a.output / 'source-proof.json').write_text(json.dumps({
    'source_sha256': sha(out), 'template_sha256': sha(template_path),
    'baseline_sha256': sha(a.baseline), 'prior_binding_sha256': sha(old_binding_path),
    'G29_native_parent_source_sha256': sha(a.inputs / 'rpmh-G29/G29-read-enable.js'),
    'stock_platform_binding_sha256': sha(platform_path),
    'reference_RSC_source_sha256': sha(source_path),
    'regulator_source_sha256': sha(reg_path), 'command_DB_decode_sha256': sha(db_path),
    'parent_algorithm': 'G29 native READ/cleanup; only names/metadata/fixed message address change',
    'native_resource_write_permitted': False,
    'known_fault_native_reads_not_repeated': ['0xb000000', '0xc7b7000', '0xc7b7008']
}, indent=2) + '\n')
print(json.dumps({'kind': a.kind, 'source_sha256': sha(out), 'nonce': binding['nonce'], 'message_address': hex(address)}))
