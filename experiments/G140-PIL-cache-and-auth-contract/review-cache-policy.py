"""Bind the cache-policy review to saved build sources and original-code replay.

Source excerpts are review evidence, not a compilation or runtime page-table
observation. This program creates a report only; it never changes eligibility.
"""
from pathlib import Path
import argparse
import hashlib
import json
import re

PINS = {
    'MU_BASECORE/UefiCpuPkg/Library/ArmMmuLib/AArch64/ArmMmuLibCore.c':
        '6abbf9d69415525bb8bf7dd1edfa0522281c811338cc25fd0a572a593bd3a0c4',
    'MU_BASECORE/MdePkg/Include/AArch64/AArch64Mmu.h':
        '3dcb677e2891c0a1b3cffe5a2834ffd9ef17c357ca1d89f3769333f55df6c44d',
    'MU_BASECORE/ArmPkg/Drivers/CpuDxe/AArch64/Mmu.c':
        '2d09e64a1799fc7e301eec703caf8de80428a7d4378c984484c68213519e9e02',
    'MU_BASECORE/ArmPkg/Library/ArmCacheMaintenanceLib/ArmCacheMaintenanceLib.c':
        '023a564661f545cd71457291252cb01b2ae6d5585dc4adb421af829f195a378b',
}
ADMISSION_SHA = '4088d4535330b39ebcec6fa7fe29e35c3ea6c8ce32b1194faa5886235535b602'


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def function(source, name):
    match = re.search(r'\b' + re.escape(name) + r'\s*\(', source)
    require(match is not None, 'source function absent')
    start = source.find('{', match.start())
    require(start >= 0, 'source function body absent')
    # The files are exactly hash-pinned. Ignore comments/string literals when
    # counting braces, while preserving offsets for the reviewed source excerpt.
    cleaned = re.sub(r'/\*.*?\*/|//[^\r\n]*|"(?:\\.|[^"\\])*"',
                     lambda m: ' ' * len(m.group()), source, flags=re.S)
    depth = 0
    for end in range(start, len(cleaned)):
        depth += int(cleaned[end] == '{') - int(cleaned[end] == '}')
        if depth == 0:
            return {'name': name, 'line': source.count('\n', 0, match.start()) + 1,
                    'source': source[match.start():end + 1]}
    raise ValueError('unbalanced source body')


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--source-root', type=Path, required=True)
    ap.add_argument('--admission', type=Path, required=True)
    ap.add_argument('--model', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    a = ap.parse_args()
    require(not a.output.exists(), 'refusing to replace existing evidence')
    sources = {}
    for name, digest in PINS.items():
        raw = (a.source_root / name).read_bytes()
        require(sha(raw) == digest, 'build source identity: ' + name)
        sources[name] = raw.decode('utf-8')
    core, header, cpu, cache = [sources[name] for name in PINS]
    snippets = [function(core, 'ArmMemoryAttributeToPageAttribute'),
                function(core, 'GcdAttributeToPageAttribute'),
                function(cpu, 'EfiAttributeToArmAttribute'),
                function(cache, 'WriteBackDataCacheRange'),
                function(cache, 'InvalidateDataCacheRange')]
    normal = lambda s: re.sub(r'\s+', ' ', s)
    require('case ARM_MEMORY_REGION_ATTRIBUTE_UNCACHED_UNBUFFERED: return TT_ATTR_INDX_MEMORY_NON_CACHEABLE | Permissions;'
            in normal(snippets[0]['source']), 'initial enum NC route changed')
    require('case EFI_MEMORY_UC: PageAttributes = TT_ATTR_INDX_DEVICE_MEMORY;'
            in normal(snippets[1]['source']), 'GCD UC route changed')
    require('case EFI_MEMORY_WC: PageAttributes = TT_ATTR_INDX_MEMORY_NON_CACHEABLE;'
            in normal(snippets[1]['source']), 'GCD WC route changed')
    require('case EFI_MEMORY_WC: ArmAttributes = TT_ATTR_INDX_MEMORY_NON_CACHEABLE;'
            in normal(snippets[2]['source']), 'CPU WC route changed')
    values = {}
    for name, expected in [('DEVICE_MEMORY', 0), ('NORMAL_MEMORY_NON_CACHEABLE', 0x44),
                           ('NORMAL_MEMORY_WRITE_THROUGH', 0xBB), ('NORMAL_MEMORY_WRITE_BACK', 0xFF)]:
        match = re.search(r'^#define\s+MAIR_ATTR_' + name + r'\s+(0x[0-9a-fA-F]+)ULL\s*$', header, re.M)
        require(match and int(match.group(1), 16) == expected, 'MAIR constant changed')
        values[name] = hex(expected)
    admission = a.admission.read_bytes()
    require(sha(admission) == ADMISSION_SHA and b'(r->ReadPar>>56)!=0xff' in admission
            and b'(r->WritePar>>56)!=0xff' in admission, 'current WB-only admission identity')
    model = json.loads(a.model.read_text())
    model_source = Path(__file__).with_name('emulate-pil-cache-auth.py')
    require(model['passed'] and model['cases'] == 20 and model['native_operations'] == 0
            and model['source_sha256'] == sha(model_source.read_bytes()), 'replay/source binding')
    by_name = {row['case']: row for row in model['results']}
    main_case = by_name['main-full-span-auth-caller']
    require(main_case['CVAC'] == 1187840 and main_case['IVAC'] == 0
            and main_case['DSB_SY'] == main_case['ISB'] == 1, 'full main clean coverage')
    post = by_name['main-post-proxy-fails-after-SCM-success']
    require(post['status'] == '0x5' and post['SCM_auth_calls_modeled'] == 1
            and post['proxy_events_modeled'] == [1, 2], 'post-auth error classification')
    result = {
        'campaign': 'G140', 'review_inputs_verified': True,
        'source_sha256': PINS, 'source_excerpts': snippets, 'MAIR_source_values': values,
        'current_WB_only_admission_sha256': ADMISSION_SHA,
        'model_sha256': sha(a.model.read_bytes()), 'model_cases': 20,
        'observations': [
            'Initial ARM UNCACHED_UNBUFFERED enum selects normal non-cacheable memory in the saved build source.',
            'GCD/CPU EFI_MEMORY_UC selects Device; EFI_MEMORY_WC selects normal non-cacheable. The labels are not interchangeable.',
            'The current CPU admission permits only raw PAR attribute FF; it would refuse a valid identity-mapped normal-NC 44 page.',
            'Original PIL373c calls761c on the full selected destination before PRE_AUTH event1 and SCM02000205, then POST_AUTH event2.',
            'Original761c walks CTR-sized lines using DC CVAC, then DSB SY and ISB. Original7680 uses IVAC instead.',
            'In the model, a PRE callback failure prevents authentication. A POST callback failure returns5 after modeled SCM success.',
            'Original event dispatch tolerates a missing/null proxy protocol and can still call authentication.',
            'Empty backup/post fields prevent modeled repeat loads. Controlled nonempty fields demonstrate retry/post-image hazards.'
        ],
        'next_decision': [
            'Keep G139 unchanged as the next physical test: capture live error and raw per-page PAR tags first.',
            'If live data shows uniform fault-free identity normal-NC44 and the reservation/footprint checks pass, evaluate a payload-specific normal-memory admission while retaining the separate WB requirement for the SCM hook page.',
            'If live data shows Device00, mixed/faulted mappings or inconsistent descriptors, correct/qualify the mapping before ordinary target data accesses; do not relabel Device as normal RAM or blindly remap to WB.',
            'The first in-window diagnostic should retain the forced stop after DTB memory setup, before payload/auth/main, on a fresh boot with physical recovery available.',
            'Before a full main authentication attempt, bind the required proxy interface and its resource effects; retain separate PRE, secure acceptance and POST results.',
            'After an accepted authentication, a later loader error does not prove a stopped processor. Do not retry/shutdown based only on the public EFI_LOAD_ERROR.'
        ],
        'primary_references': [
            {'url': 'https://uefi.org/sites/default/files/resources/UEFI_Spec_2_10_Aug29.pdf',
             'location': '2.3.6.1, Table2.5', 'supports': 'AArch64 UC/Device00 versus WC/normal-NC44 mapping'},
            {'url': 'https://support.arm.com/documentation/111107/2026-09/AArch64-Instructions/DC-CVAC--Data-or-unified-Cache-line-Clean-by-VA-to-PoC',
             'supports': 'DC CVAC names cache clean by virtual address to the point of coherency'}
        ],
        'native_operations': 0, 'native_G139_boots': 0, 'eligibility_granted': False,
        'limits': [
            'This is a pinned-source review and controlled replay, not a compiled MMU-path or live page-table proof.',
            'The current G139 OPIL collector deliberately reports raw tags and grants no eligibility; no diagnostic/driver/release is changed.',
            'Cache effects, CTR values, proxy resources and SCM results are modeled; no native coherence, secure acceptance or hardware state is established.',
            'The proxy PRE callback executes after the clean pass; its resource/payload effects remain a separate contract to qualify.',
            'Fault-free translations and intended carveouts do not themselves establish stage-2 or DMA/display ownership.',
            'All six project goals remain active/incomplete; no new DSP, GLINK, charging or physical touch acceptance is claimed.'
        ]}
    a.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: result[k] for k in ('campaign', 'review_inputs_verified', 'model_cases', 'native_operations', 'eligibility_granted')}))


if __name__ == '__main__':
    main()
