#!/usr/bin/env python3
"""Stage a compiled G1330 object set and explicitly selected external libraries.

Checks direct external-symbol coverage and ARM64 file headers. This is not a
linker or library provenance certificate. Never invokes link.exe or any driver.
"""
import argparse
import collections
import hashlib
import json
from pathlib import Path
import shutil
import subprocess


def digest(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--coff', type=Path, required=True)
    p.add_argument('--nm', type=Path, required=True)
    p.add_argument('--readobj', type=Path, required=True)
    p.add_argument('--library', type=Path, action='append', required=True)
    p.add_argument('--allow-mixed-archive', type=Path, action='append', default=[],
                   help='Explicitly admit an archive with ARM64 plus companion members; linker must select actual ARM64 members')
    p.add_argument('--out', type=Path, required=True)
    a = p.parse_args()
    receipt = json.loads((a.coff / 'receipt.json').read_text())
    if not receipt['all_compiled']:
        p.error('All KMD translation units must compile successfully first')
    objects = []
    for unit in receipt['units']:
        obj = a.coff / (unit['unit'].replace('/', '_') + '.obj')
        if digest(obj) != unit['object_sha256']:
            p.error('Object differs from compile receipt: ' + str(obj))
        objects.append(obj)
    libraries = [x.resolve(strict=True) for x in a.library]
    if len({x.name.lower() for x in libraries}) != len(libraries):
        p.error('Library basenames must be unique')
    allowed_mixed = {x.resolve(strict=True) for x in a.allow_mixed_archive}
    if not allowed_mixed.issubset(set(libraries)):
        p.error('Mixed-archive exception must name a selected library')
    a.out.mkdir(parents=True, exist_ok=False)
    definitions = collections.defaultdict(list)
    undefined = collections.defaultdict(list)
    providers = collections.defaultdict(set)
    header_receipts = []
    for path in objects + libraries:
        header = subprocess.check_output([str(a.readobj), '--file-headers', str(path)], text=True)
        # Actual objects must be ARM64. A mixed library needs explicit selection;
        # symbol coverage cannot certify which companion member native link selects.
        machines = [x.strip() for x in header.splitlines() if x.strip().startswith('Machine:')]
        arches = [x.strip() for x in header.splitlines() if x.strip().startswith('Arch:')]
        if not machines and not arches:
            p.error('No recognized COFF machine: ' + str(path))
        mixed = any('ARM64 (' not in x for x in machines) or any(x != 'Arch: aarch64' for x in arches)
        if mixed and (path not in allowed_mixed or not any('ARM64 (' in x for x in machines)):
            p.error('Non-ARM64 input without explicit companion-archive selection: ' + str(path))
        header_receipts.append({'name': path.name, 'sha256': digest(path), 'mixed_archive_explicitly_admitted': mixed,
                                'machines': dict(collections.Counter(machines)),
                                'file_headers_sha256': hashlib.sha256(header.encode()).hexdigest()})
        output = subprocess.check_output([str(a.nm), '--extern-only', '--format=posix', str(path)], text=True)
        for line in output.splitlines():
            v = line.split()
            if len(v) < 2 or v[1] not in ('U', 'T', 'D', 'R', 'B', 'W', 'C', 'I', 'S'):
                continue
            name, kind = v[:2]
            if path in libraries:
                if kind != 'U':
                    providers[name].add(path.name)
            elif kind == 'U':
                undefined[name].append(path.name)
            else:
                definitions[name].append(path.name)
    external = sorted(set(undefined) - set(definitions))
    uncovered = [x for x in external if x not in providers]
    symbols = [{'name': x, 'referenced_by': undefined[x],
                'provider_libraries': sorted(providers[x])} for x in external]
    report = {'schema': 'G1330-link-inputs/1', 'external_symbols': symbols,
              'uncovered': uncovered, 'input_headers': header_receipts,
              'duplicate_object_definition_candidates': {k: v for k, v in definitions.items() if len(v) > 1},
              'native_link_executed': False, 'abi_qualified': False,
              'note': 'Direct symbol coverage only; archive-member selection, COMDAT, directives, relocation and import closure require an actual native link.'}
    (a.out / 'inputs.json').write_text(json.dumps(report, indent=2) + '\n')
    if uncovered:
        raise SystemExit('Uncovered direct symbols: ' + ', '.join(uncovered))
    for path in objects + libraries:
        shutil.copy2(path, a.out / path.name)
    response = (a.coff / 'kmd-objects.rsp').read_text()
    response += ''.join('"' + x.name + '"\n' for x in libraries)
    (a.out / 'native-link.rsp').write_text(response)
    print(a.out / 'inputs.json')


if __name__ == '__main__':
    main()
