"""Reproduce the historical, consumed G29 READ source; never deploy or run it."""
import argparse
import hashlib
import json
from pathlib import Path

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--binding', required=True, type=Path)
p.add_argument('--shadow-plan', required=True, type=Path)
p.add_argument('--template', required=True, type=Path)
p.add_argument('--output', required=True, type=Path)
a = p.parse_args()
assert not a.output.exists()
b = json.loads(a.binding.read_text())
s = json.loads(a.shadow_plan.read_text())
assert b['nonce'] == 'b38bfc6d141aeca5'
assert b['phone_session'] == '00000000000000000000000000000000'
assert b['request_address'] == '0x40804' and b['request_MSGID'] == '0x108'
assert b['no_supply_vote_or_PMIC_configuration_write']
addresses = {k: int(v, 16) for k, v in s['fields'].items()}
assert b['baseline'].keys() == addresses.keys()
source = 'var G29_Q_BINDING=' + json.dumps(b, separators=(',', ':')) + ';\n'
source += 'var G29_Q_ADDR=' + json.dumps(addresses, separators=(',', ':')) + ';\n'
source += a.template.read_text()
sha = hashlib.sha256(source.encode()).hexdigest()
assert sha == '85c622d6200bb9fd2615575c9e4fd299879f9b7e145bd2fbcd4cccad9f150799'
a.output.write_text(source)
print(json.dumps({'historical_consumed_source_reproduced': True, 'sha256': sha, 'deploy_or_run': False}))
