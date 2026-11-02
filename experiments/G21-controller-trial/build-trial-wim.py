"""Run inside the existing build VM; keep the qualified image intact."""
from pathlib import Path
import datetime
import hashlib
import json
import shutil
import subprocess

W = Path('/path/to/user/Documents/Codex/2026-10-20/sta/work/maintenance-G18/gpio-G21')
P = W / 'private'
state = W / 'WIM-build-state.json'
target = Path('/tmp/G21-gpio-native-v1.wim')
source = Path('/tmp/G20-canary-native-v2.wim')
assert not target.exists() and not state.exists()
def digest(p):
    with p.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()
assert digest(source) == 'b21bee40f1f487f11922e0b857133e0e1c9504adaf775410948957c43febc8f0'
receipt = {'phase': 'copy_qualified_trial', 'source_sha256': digest(source), 'commands': []}
def save():
    receipt['updated_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    tmp = state.with_suffix('.tmp')
    tmp.write_text(json.dumps(receipt, indent=2) + '\n')
    tmp.replace(state)
def run(phase, argv):
    receipt['phase'] = phase
    save()
    log = P / (phase + '.log')
    assert not log.exists()
    print(phase, flush=True)
    with log.open('xb') as f:
        result = subprocess.run(argv, stdout=f, stderr=subprocess.STDOUT)
    receipt['commands'].append({'phase': phase, 'argv': argv, 'exit_code': result.returncode,
                                'log_sha256': digest(log)})
    save()
    assert result.returncode == 0, log
save()
shutil.copyfile(source, target)
assert digest(target) == receipt['source_sha256']
run('verify-G21-before-update', ['wimlib-imagex', 'verify', str(target)])
run('update-G21-controller', ['wimlib-imagex', 'update', str(target), '1', '--check',
                             '--command=add "' + str(P / 'acpitabl.dat') + '" /Windows/System32/acpitabl.dat'])
run('verify-G21-after-update', ['wimlib-imagex', 'verify', str(target)])
receipt.update(phase='verified_VM_native_trial', bytes=target.stat().st_size,
               sha256=digest(target), target=str(target))
save()
print(json.dumps({k: receipt[k] for k in ['phase', 'bytes', 'sha256']}), flush=True)
