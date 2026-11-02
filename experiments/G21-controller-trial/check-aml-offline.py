"""Execute the compiled AML query paths with ACPICA, without hardware regions."""
from pathlib import Path
import hashlib
import json
import subprocess

W = Path(__file__).resolve().parent
P = W / 'private'
cases = []
methods = []
for family, uuid in [('T', '98b9b2a4-1663-4a5f-82f2-c6c99a394726'), ('P', '921b0fd4-567c-43a0-bb14-2648f7b2a18c')]:
    for selector in range(6):
        name = '%s%03d' % (family, selector)
        cases.append(name)
        methods.append('Method (%s, 0) { Return (\\_SB.GIO0._DSM (ToUUID ("%s"), Zero, %d, Package (0) {})) }' % (name, uuid, selector))
source = 'DefinitionBlock ("", "SSDT", 2, "OPEN  ", "G21TEST ", 1) {\nExternal (\\_SB.GIO0._DSM, MethodObj)\n' + '\n'.join(methods) + '\n}\n'
path = P / 'query-check.dsl'
assert not path.exists()
path.write_text(source)
subprocess.run(['iasl', '-tc', str(path)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
commands = '; '.join('execute \\' + n for n in cases)
r = subprocess.run(['acpiexec', '-b', commands, str(P / 'acpitabl.dat'), str(path.with_suffix('.aml'))], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
log = P / 'AML-execution-check.log'
assert not log.exists()
log.write_bytes(r.stdout)
assert r.returncode == 0
s = r.stdout.decode(errors='replace')
assert 'failed' not in s.lower() and 'AE_' not in s
result = {}
for i, name in enumerate(cases):
    start = s.index('Evaluating \\' + name)
    end = s.index('Evaluating \\' + cases[i+1]) if i+1 < len(cases) else len(s)
    result[name] = s[start:end]
assert '[Package] Contains 38 Elements:' in result['T004']
assert '[Package] Contains 2 Elements:' in result['P002']
assert result['P002'].count('[Package] Contains 3 Elements:') == 2
for name, value in {'T001': 0, 'T002': 210, 'T003': 4096, 'T005': 0,
                    'P001': 1, 'P003': 0xb220010, 'P004': 0xb220110, 'P005': 0x4330}.items():
    assert '[Integer] = %016X' % value in result[name], (name, result[name])
assert result['T004'].count('[Integer]') == 38
assert result['P002'].count('[Integer]') == 6
receipt = {'phase': 'compiled_AML_executed_offline', 'queries': 12,
           'primary_selector4_integer_count': 38, 'PDC_wake_records': 2,
           'PDC_record_integer_count': 3, 'scalar_contract_checks_pass': True,
           'log_sha256': hashlib.sha256(r.stdout).hexdigest(),
           'scope': 'ACPICA execution and return shapes; Windows ACPI IOCTL marshalling and live driver binding remain untested.'}
(W / 'AML-offline-result.json').write_text(json.dumps(receipt, indent=2) + '\n')
print(json.dumps(receipt, indent=2))
