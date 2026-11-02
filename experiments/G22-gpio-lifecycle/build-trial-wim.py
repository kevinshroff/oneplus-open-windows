"""Run in the existing Linux VM; reuse its temporary image after backup checks."""
from pathlib import Path
import datetime, hashlib, json, subprocess

W = Path('/path/to/user/Documents/Codex/2026-10-20/sta/work/maintenance-G18/gpio-G22')
P = W / 'private'
state = W / 'WIM-build-state.json'
source = Path('/tmp/G21-gpio-native-v1.wim')
target = Path('/tmp/G22-gpio-lifecycle-v1.wim')
retained = W.parent / 'gpio-G21/private/G21-gpio-native-v1.wim'
source_sha = 'b27fade499d2b218e6ab1b965afccc920b5b87ae7683aa3bcd6e6c971002c175'
def digest(p):
    with p.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()
assert not state.exists() and not target.exists()
assert digest(source) == digest(retained) == source_sha
driver = P / 'G22-qcgpio-development.sys'
assert digest(driver) == '4df56f98b47a988a491e14501547b6da98b277a01881deffdf1b4ca315e178b3'
table = P / 'acpitabl.dat'
assert digest(table) == '3fa138e8a376134a082aecc8d13c7d07c0aa335d915f6dc11a1b3d0ef4d97a65'
r = {'phase': 'backup_verified_before_temporary_VM_image_reuse', 'source_sha256': source_sha,
     'source_retained_on_Mac': str(retained), 'target': str(target), 'commands': []}
def save():
    r['updated_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    temp = state.with_suffix('.tmp')
    temp.write_text(json.dumps(r, indent=2) + '\n')
    temp.replace(state)
def run(phase, argv, data=None):
    r['phase'] = phase
    save()
    log = P / (phase + '.log')
    print(phase, flush=True)
    with log.open('xb') as f:
        result = subprocess.run(argv, input=data, stdout=f, stderr=subprocess.STDOUT)
    r['commands'].append({'phase': phase, 'argv': argv, 'exit_code': result.returncode,
                          'log_sha256': digest(log)})
    save()
    assert result.returncode == 0, log
save()
source.rename(target)  # No second ~588 MB allocation on the small VM filesystem.
run('verify-G22-before', ['wimlib-imagex', 'verify', str(target)])
paths = ['Windows/System32/acpitabl.dat',
         'Windows/System32/DriverStore/FileRepository/qcgpio_i.inf_arm64_41e106a2e4fca1b9/qcgpio_i.sys',
         'Windows/WinSxS/arm64_dual_qcgpio_i.inf_31bf3856ad364e35_10.0.26100.8115_none_ec59ac755c635f0a/qcgpio_i.sys']
commands = '\n'.join('add "' + str(table if i == 0 else driver) + '" "/' + path + '"'
                     for i, path in enumerate(paths)) + '\n'
(P / 'G22-WIM-update-commands.txt').write_text(commands)
run('update-G22-lifecycle', ['wimlib-imagex', 'update', str(target), '1', '--check'], commands.encode())
run('verify-G22-after', ['wimlib-imagex', 'verify', str(target)])
for i, path in enumerate(paths):
    data = subprocess.check_output(['wimlib-imagex', 'extract', str(target), '1', path, '--to-stdout'])
    assert data == (table if i == 0 else driver).read_bytes(), path
r.update(phase='verified_VM_native_trial', bytes=target.stat().st_size,
         sha256=digest(target), changed_paths=paths)
save()
print(json.dumps({k: r[k] for k in ['phase', 'bytes', 'sha256']}), flush=True)
