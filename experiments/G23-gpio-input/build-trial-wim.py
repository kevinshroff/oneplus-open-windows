"""Run inside the existing Linux VM; append one ACPI table to the G22 trial.

The VM has little free space. Reuse its temporary image only after checking
the full independent Mac-retained G22 backup. Never edit the retained backup.
"""
from pathlib import Path
import datetime, hashlib, json, subprocess

W = Path('/path/to/user/Documents/Codex/2026-10-20/sta/work/maintenance-G18/gpio-G23')
P = W / 'private'
state = W / 'WIM-build-state.json'
source = Path('/tmp/G22-gpio-lifecycle-v2.wim')
target = Path('/tmp/G23-gpio-input-v1.wim')
retained = W.parent / 'gpio-G22/private/G22-gpio-lifecycle-v2.wim'
source_sha = 'a8d3bb0ddaecb93b400e25c2cfea53497855374491373b9b864207bd26563f53'
def digest(p):
    with p.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()
assert not state.exists() and not target.exists()
assert digest(source) == digest(retained) == source_sha
table = P / 'acpitabl.dat'
assert digest(table) == '381f5112ccc1d4e8b1505d2863f3470e1c0f6da9963dedf03602f111fb98be77'
r = {'phase': 'backup_verified_before_VM_temporary_image_reuse', 'source_sha256': source_sha,
     'retained_source': str(retained), 'target': str(target), 'commands': []}
def save():
    r['updated_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    temp = state.with_suffix('.tmp')
    temp.write_text(json.dumps(r, indent=2) + '\n')
    temp.replace(state)
def run(phase, argv, data=None):
    r['phase'] = phase
    save()
    log = P / (phase + '.log')
    with log.open('xb') as f:
        result = subprocess.run(argv, input=data, stdout=f, stderr=subprocess.STDOUT)
    r['commands'].append({'phase': phase, 'argv': argv, 'exit_code': result.returncode,
                          'log_sha256': digest(log)})
    save()
    assert result.returncode == 0, log
    print(phase, flush=True)
save()
source.rename(target)
run('verify-G23-before', ['wimlib-imagex', 'verify', str(target)])
path = 'Windows/System32/acpitabl.dat'
command = 'add "' + str(table) + '" "/' + path + '"\n'
(P / 'G23-WIM-update-commands.txt').write_text(command)
run('update-G23-input', ['wimlib-imagex', 'update', str(target), '1', '--check'], command.encode())
run('verify-G23-after', ['wimlib-imagex', 'verify', str(target)])
assert subprocess.check_output(['wimlib-imagex', 'extract', str(target), '1', path, '--to-stdout']) == table.read_bytes()
r.update(phase='verified_VM_native_trial', bytes=target.stat().st_size,
         sha256=digest(target), changed_paths=[path])
save()
print(json.dumps({k: r[k] for k in ['phase', 'bytes', 'sha256']}), flush=True)
