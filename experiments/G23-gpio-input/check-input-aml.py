"""Reproduce the handler-availability/read-path checks in an ACPICA simulator."""
from pathlib import Path
import hashlib, json, re, subprocess

W = Path(__file__).resolve().parent
log = W / 'private/GPIO-AML-input-check.log'
commands = [('_REG', '8 0'), ('RDP0', ''), ('RDP1', ''), ('RCNT', ''),
            ('_REG', '8 1'), ('_STA', ''), ('R025', ''), ('R174', ''), ('RCNT', ''),
            ('_STA', ''), ('RCNT', ''), ('_REG', '8 0'), ('_STA', ''), ('RCNT', '')]
if not log.exists():
    batch = '; '.join('execute \\_SB.GIO0.' + method + (' ' + args if args else '')
                      for method, args in commands)
    run = subprocess.run(['acpiexec', '-di', '-vr', '-b', batch, str(W / 'private/acpitabl.dat')],
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    log.write_bytes(run.stdout)
    assert run.returncode == 0
s = log.read_text(errors='replace')
assert 'AE_' not in s and 'failed' not in s.lower()
values = []
for section in re.split(r'(?m)^Evaluating ', s)[1:]:
    match = re.search(r'\[Integer\] = ([0-9A-F]{16})', section)
    values.append({'method': section.splitlines()[0],
                   'return': int(match[1], 16) if match else None})
assert len(values) == len(commands) == 14
assert [v['method'] for v in values] == ['\\_SB.GIO0.' + method for method, _ in commands]
assert [values[i]['return'] for i in (1, 2)] == [0xbad00008] * 2
assert [values[i]['return'] for i in (5, 9, 12)] == [15] * 3
assert values[6]['return'] in (0, 1) and values[7]['return'] in (0, 1)
counts = [values[i]['return'] for i in (3, 8, 10, 13)]
assert counts[1] == counts[0] + 2 and counts[2] == counts[1] + 2 and counts[3] == counts[2]
table = (W / 'private/acpitabl.dat').read_bytes()
assert sum(table) % 256 == 0 and table.count(b'\\_SB.GIO0\0') == 2
result = {'phase': 'compiled_AML_input_guard_and_connections_verified_offline',
          'queries': values, 'read_counts': counts, 'connected_calls_add_two_reads': True,
          'disconnected_calls_add_no_reads': True, 'input_only_resource_sources': '\\_SB.GIO0',
          'resource_source_occurrences': 2, 'DSDT_bytes': len(table),
          'DSDT_sha256': hashlib.sha256(table).hexdigest(),
          'log_sha256': hashlib.sha256(log.read_bytes()).hexdigest(),
          'limits': 'ACPICA simulates GPIO handlers. Native Windows requests, pin configuration, actual voltage levels and IRQ delivery remain unqualified.'}
output = W / 'AML-input-result.json'
if output.exists():
    assert json.loads(output.read_text()) == result
else:
    output.write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps({'phase': result['phase'], 'read_counts': counts}))
