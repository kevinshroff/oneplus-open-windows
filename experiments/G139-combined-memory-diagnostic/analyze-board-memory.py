"""Resolve reserved-memory descriptions from previously captured stock FDTs.

This inspects fixed, hash-pinned artifacts only. Overlay target resolution is
not a complete Android overlay application, bootloader patch trace or DMA lease.
"""
from pathlib import Path
import argparse
import hashlib
import json
import struct
import subprocess

from fdtree import Fdt

WINDOW = (0x9E980000, 0xA3280000)
DTB = (0x9E980000, 0x80000)
MAIN = (0x9EA00000, 0x4880000)
PINS = {
    'vendor_boot_a.img': 'd68adc47ca56b31127702be2881ea2ee9d4b383aa7be3c1b067f41e3201a1edc',
    'vendor_boot_b.img': 'c7b6b9c861fe5271f31363439ec959a25ce83b95eac2c2d3b4a2fa8f29b0eea4',
    'vendor_boot_a-dtb-region.bin': '1589f80868b78a13fcc1003576855f0894253a3e10f31602cc1c65b044c1bea1',
    'vendor_boot_b-dtb-region.bin': '1589f80868b78a13fcc1003576855f0894253a3e10f31602cc1c65b044c1bea1',
    'dtbo_a.img': 'b5de434cd5a49ae0ef62eca2c4f4d76a9ccb1f6e8892fcc3de1e43078ef7700d',
    'dtbo_b.img': 'b24c6ca34649f069a3f034b0ff9f491ccafa8595afd6711defe18dc871b13e46',
}
BASE_PINS = [
    'bdabb8c172893dfe004ba976df3778907f975eef8087db838de92070990c9ca3',
    '98d3e43d57a36a12d6bc6b76dde50cff34f115779da40d3ac06d5553b1a38356',
    '65d34e457f0dc9dff9c6bb7a18963dbe07fa1449499a5d2cb89f2fb3bf2210ef',
    'bf5287b7e033a55ea1d5e46e328a31de40653e01765dd3550f257bf4a6c82f69',
    '447ed770db43d57f9b69bbd189cc3fb5a5345022959c1e24918b7a431420572c',
]
OVERLAY_PIN = '55523ac7d50177a23c428e768e6478337eadf01d74f7c29068bb5e3b6387b706'
BOOT_PIN = 'f0854f17171351b60254538941044e68cae283f1f6c9243faa14b71badbc2e29'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def interval(base, size):
    require(0 <= base < 1 << 64 and 0 <= size <= (1 << 64) - base,
            '64-bit range overflow')
    return {'base': hex(base), 'size': hex(size), 'end_exclusive': hex(base + size),
            'overlaps_proposed_window': size > 0 and base < WINDOW[1] and base + size > WINDOW[0]}


def ranges(raw):
    require(len(raw) % 16 == 0, 'expected two address and two size cells')
    return [interval(*struct.unpack_from('>QQ', raw, i)) for i in range(0, len(raw), 16)]


def reservations(data):
    """Inspect the FDT's separate reservation block, which fdtree does not expose."""
    total, so, st, ro = struct.unpack_from('>4I', data, 4)
    require(ro >= 40 and ro % 8 == 0, 'reservation block alignment')
    result = []
    for off in range(ro, total - 15, 16):
        require(off + 16 <= min(so, st), 'reservation block intersects structure/strings')
        base, size = struct.unpack_from('>QQ', data, off)
        if (base, size) == (0, 0):
            return result
        require(size > 0, 'nonterminating zero-size reservation')
        result.append(interval(base, size))
    raise ValueError('missing reservation terminator')


def base_observations(data, index):
    f = Fdt(data)
    require(f.total == len(data), 'base tree trailing data')
    reserve = reservations(data)
    root = '/reserved-memory'
    require(f.cells(root, '#address-cells') == [2] and f.cells(root, '#size-cells') == [2]
            and f.nodes[root]['ranges'] == b'', 'reserved-memory cell/address translation contract')
    fixed, dynamic = [], []
    for path, props in f.nodes.items():
        if not path.startswith(root + '/'):
            continue
        require('/' not in path[len(root) + 1:], 'unexpected nested reserved-memory node')
        if 'reg' in props:
            fixed.append({'path': path, 'no_map': 'no-map' in props,
                          'raw_reg': props['reg'].hex(), 'ranges': ranges(props['reg'])})
        else:
            dynamic.append({'path': path, 'properties': {
                k: props[k].hex() for k in ('size', 'alloc-ranges', 'alignment', 'reusable') if k in props}})
    overlaps = [row for row in fixed if any(x['overlaps_proposed_window'] for x in row['ranges'])]
    compatible = f.strings('/', 'compatible')
    candidate = compatible in (['qcom,kalama'], ['qcom,kalamap'])
    record = {'index': index, 'sha256': sha(data), 'compatible': compatible,
              'candidate_Kalama_family': candidate, 'reservation_block': reserve}
    if candidate:
        expected = {'/reserved-memory/q6_adsp_dtb_region@9e980000': DTB,
                    '/reserved-memory/adspslpi_region@9ea00000': MAIN}
        require({row['path'] for row in overlaps} == set(expected), 'unexpected fixed overlap')
        for row in overlaps:
            require(row['no_map'] and row['ranges'] == [interval(*expected[row['path']])],
                    'ADSP region differs from captured metadata')
        require(not any(row['overlaps_proposed_window'] for row in reserve), 'FDT reservation-block overlap')
        heap = f.nodes['/reserved-memory/demura_heap_region']
        require('reg' not in heap and len(heap['size']) == 8, 'expected dynamic Demura heap')
        heap_ranges = ranges(heap['alloc-ranges'])
        require(heap_ranges and all(int(row['base'], 16) >= 1 << 32 for row in heap_ranges),
                'Demura heap allocation range reaches low reserved memory')
        target_phandles = {f.cells(path, 'phandle')[0]: path for path in expected}
        consumers = []
        for path, props in f.nodes.items():
            if 'memory-region' in props:
                cells = f.cells(path, 'memory-region')
                if any(value in target_phandles for value in cells):
                    consumers.append({'path': path, 'memory_regions': [target_phandles.get(x, hex(x)) for x in cells]})
        record.update(fixed_reserved_regions=len(fixed), fixed_window_overlaps=overlaps,
                      dynamic_region_count=len(dynamic), dynamic_regions=dynamic,
                      Demura_heap={'size': hex(struct.unpack('>Q', heap['size'])[0]),
                                   'alignment': hex(struct.unpack('>Q', heap['alignment'])[0]),
                                   'alloc_ranges': heap_ranges, 'reusable': 'reusable' in heap},
                      ADSP_memory_region_consumers=consumers)
    return f, record


def overlay_observations(base, overlay):
    """Resolve every fragment's target; do not apply unrelated property fixups."""
    fragments = {p for p in overlay.nodes if p.count('/') == 1 and p.startswith('/fragment@')}
    external = {}
    for symbol in overlay.nodes['/__fixups__']:
        for site in overlay.strings('/__fixups__', symbol):
            external.setdefault(site, []).append(symbol)
    local = overlay.phandles()
    base_handles = base.phandles()
    memo = {}

    def resolve(fragment, ancestors=()):
        require(fragment in fragments and fragment not in ancestors, 'overlay fragment target cycle')
        if fragment in memo:
            return memo[fragment]
        props = overlay.nodes[fragment]
        if 'target-path' in props:
            require('target' not in props, 'ambiguous target forms')
            paths = overlay.strings(fragment, 'target-path')
        else:
            cells = overlay.cells(fragment, 'target')
            require(len(cells) == 1, 'fragment target length')
            symbol = external.get(fragment + ':target:0', [])
            if symbol:
                require(len(symbol) == 1, 'ambiguous external target fixup')
                paths = base.strings('/__symbols__', symbol[0])
            elif 'target' in overlay.nodes.get('/__local_fixups__' + fragment, {}):
                require(overlay.cells('/__local_fixups__' + fragment, 'target') == [0], 'local target offset')
                target = local[cells[0]]
                require('/__overlay__' in target, 'local target outside overlay')
                parent, suffix = target.split('/__overlay__', 1)
                paths = [p.rstrip('/') + suffix for p in resolve(parent, ancestors + (fragment,))]
            else:
                paths = [base_handles[cells[0]]]
        require(paths and all(p.startswith('/') and '/..' not in p and '//' not in p for p in paths),
                'invalid resolved path')
        memo[fragment] = sorted(set(paths))
        return memo[fragment]

    changes = []
    relevant = ('reg', 'size', 'alloc-ranges', 'alignment', 'label', 'no-map', 'reusable',
                '#address-cells', '#size-cells', 'ranges')
    for fragment in sorted(fragments):
        for target in resolve(fragment):
            prefix = fragment + '/__overlay__'
            for path, props in overlay.nodes.items():
                if path != prefix and not path.startswith(prefix + '/'):
                    continue
                dest = target.rstrip('/') + path[len(prefix):] or '/'
                if dest != '/reserved-memory' and not dest.startswith('/reserved-memory/'):
                    continue
                # Compiled overlays can contain fixups; address ranges must be literal data here.
                for key in ('reg', 'size', 'alloc-ranges', '#address-cells', '#size-cells', 'ranges'):
                    require(not any(site.startswith(path + ':' + key + ':') for site in external),
                            'memory range has an external relocation')
                    require(key not in overlay.nodes.get('/__local_fixups__' + path, {}),
                            'memory range has a local relocation')
                for key in ('#address-cells', '#size-cells'):
                    if key in props:
                        require(overlay.cells(path, key) == [2], 'overlay changes reserved cell width')
                if 'ranges' in props:
                    require(props['ranges'] == b'', 'overlay changes reserved translation')
                record = {'fragment': fragment, 'target': target, 'path': dest,
                          'raw_properties': {k: props[k].hex() for k in relevant if k in props}}
                if 'reg' in props:
                    record['ranges'] = ranges(props['reg'])
                    record['zero_size_placeholder'] = all(int(x['size'], 16) == 0 for x in record['ranges'])
                    require(not any(x['overlaps_proposed_window'] for x in record['ranges']),
                            'overlay introduces a conflicting fixed reservation')
                changes.append(record)
    require(len(memo) == len(fragments), 'fragment target coverage incomplete')
    return {'fragment_targets_resolved': len(memo),
            'ambiguous_nonreserved_targets': {p: v for p, v in memo.items() if len(v) != 1},
            'reserved_memory_changes': changes,
            'scope': 'Every fragment target resolved; literal reserved-memory changes inspected. Not a full overlay merge.'}


def independent_decode(tool, selections):
    """Compare property bytes to libfdt without executing any captured firmware."""
    version = subprocess.run([str(tool), '--version'], check=True, capture_output=True, text=True).stdout.strip()
    require(version == 'Version: DTC 1.8.1', 'independent decoder version')
    records = []
    for path, expected, tree in selections:
        require(path.read_bytes() == expected, 'extracted child differs from captured parent')
        pairs = []
        for node, props in tree.nodes.items():
            if (node == '/' or node.startswith('/reserved-memory')
                    or node.startswith('/fragment@')
                    or node in ('/__symbols__', '/__fixups__')
                    or 'memory-region' in props):
                if node.startswith('/fragment@') and '/__overlay__' in node:
                    # All fragment target fields are compared; only reserved literal
                    # fields need comparing inside an overlay subtree.
                    keys = [k for k in props if k in ('reg', 'size', 'alloc-ranges',
                            'alignment', 'label', 'no-map', 'reusable', '#address-cells',
                            '#size-cells', 'ranges')]
                else:
                    keys = list(props)
                pairs.extend((node, key) for key in keys)
        args = [str(tool), '-t', 'bx', str(path)] + [item for pair in pairs for item in pair]
        out = subprocess.run(args, check=True, capture_output=True, text=True).stdout.splitlines()
        require(len(out) == len(pairs), 'libfdt output count')
        for (node, key), line in zip(pairs, out):
            require(bytes(int(x, 16) for x in line.split()) == tree.nodes[node][key],
                    'libfdt property contradiction: ' + node + ':' + key)
        children = subprocess.run([str(tool), '-l', str(path), '/'], check=True,
                                  capture_output=True, text=True).stdout.splitlines()
        expected_children = [p[1:] for p in tree.nodes if p != '/' and p.count('/') == 1]
        require(children == expected_children, 'libfdt root child inventory contradiction')
        records.append({'file': path.name, 'sha256': sha(expected),
                        'property_queries': len(pairs), 'root_child_inventory_matches': True})
    return {'passed': True, 'tool_version': version, 'tool_sha256': sha(tool.read_bytes()),
            'files': records, 'property_queries': sum(x['property_queries'] for x in records),
            'native_phone_operations': 0}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--stock-dir', type=Path, required=True)
    ap.add_argument('--boot-fdt', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--fdtget', type=Path, help='Optional independent libfdt 1.8.1 property-byte comparison')
    a = ap.parse_args()
    require(not a.output.exists(), 'refusing to replace existing evidence')
    blobs = {}
    for name, digest in PINS.items():
        data = (a.stock_dir / name).read_bytes()
        require(sha(data) == digest, 'captured artifact identity: ' + name)
        blobs[name] = data
    candidates, base_reports, selections = {}, [], []
    for slot in ('a', 'b'):
        header = blobs['vendor_boot_' + slot + '.img']
        require(header[:8] == b'VNDRBOOT' and struct.unpack_from('<II', header, 8) == (4, 4096),
                'vendor boot header')
        hs, ds = struct.unpack_from('<II', header, 2096)
        ramdisk_size = struct.unpack_from('<I', header, 24)[0]
        offset = ((hs + 4095) & ~4095) + ((ramdisk_size + 4095) & ~4095)
        require(hs == 2128 and ds == 2536109 and offset == {'a': 20361216, 'b': 20434944}[slot],
                'vendor boot DTB section bounds')
        data = blobs['vendor_boot_' + slot + '-dtb-region.bin']
        off, index = 0, 0
        while off < len(data):
            require(index < 5 and len(data) - off >= 40, 'concatenated FDT count/bounds')
            size = struct.unpack_from('>I', data, off + 4)[0]
            require(40 <= size <= len(data) - off, 'concatenated FDT size')
            child = data[off:off + size]
            require(sha(child) == BASE_PINS[index], 'concatenated FDT identity')
            f, row = base_observations(child, index)
            row.update(slot=slot, captured_DTB_section_offset=offset, offset_in_section=off)
            base_reports.append(row)
            if row['candidate_Kalama_family']:
                candidates[(slot, index)] = f
            selections.append((a.stock_dir / ('vendor_boot_' + slot + '-base-' + str(index) + '.dtb'), child, f))
            off += size
            index += 1
        require(index == 5 and off == ds, 'concatenated FDT coverage')
    overlays = {}
    for slot in ('a', 'b'):
        data = blobs['dtbo_' + slot + '.img']
        magic, total, hs, es, count, eo, page, version = struct.unpack_from('>8I', data)
        require((magic, hs, es, count, eo, page, version) == (0xD7B7AB1E, 32, 32, 3, 32, 4096, 0)
                and eo + count * es <= total <= len(data), 'DTBO table bounds/format')
        found = []
        intervals = []
        for i in range(count):
            size, off = struct.unpack_from('>II', data, eo + i * es)
            require(size >= 40 and off >= eo + count * es and size <= total - off, 'DTBO entry bounds')
            require(not any(off < end and off + size > start for start, end in intervals), 'overlapping DTBO entries')
            intervals.append((off, off + size))
            child = data[off:off + size]
            tree = Fdt(child)
            require(tree.total == size and not reservations(child), 'DTBO internal bounds/reservations')
            if sha(child) == OVERLAY_PIN:
                found.append((i, tree))
                selections.append((a.stock_dir / ('dtbo_' + slot + '-' + str(i) + '.dtb'), child, tree))
        require(len(found) == 1, 'Kalama family overlay selection by artifact identity')
        i, tree = found[0]
        require(i == {'a': 1, 'b': 2}[slot], 'overlay order changed')
        overlays[slot] = tree
    resolved = []
    for (slot, index), base in candidates.items():
        row = overlay_observations(base, overlays[slot])
        row.update(slot=slot, base_index=index)
        resolved.append(row)
    boot = a.boot_fdt.read_bytes()
    require(sha(boot) == BOOT_PIN, 'saved native boot FDT identity')
    f = Fdt(boot)
    boot_reservations = reservations(boot)
    selections.append((a.boot_fdt, boot, f))
    result = {'passed': True, 'campaign': 'G139 offline board memory analysis',
              'source_artifacts': {name: {'sha256': PINS[name], 'bytes': len(data)} for name, data in blobs.items()},
              'base_trees': base_reports, 'Kalama_candidate_count': len(candidates),
              'unique_Kalama_candidate_contents': len({r['sha256'] for r in base_reports if r['candidate_Kalama_family']}),
              'family_overlay_sha256': OVERLAY_PIN, 'overlay_resolutions': resolved,
              'saved_native_boot_FDT': {'sha256': sha(boot), 'bytes': len(boot), 'nodes': len(f.nodes),
                                       'reservation_block': boot_reservations,
                                       'reserved_memory_nodes': [p for p in f.nodes if p.startswith('/reserved-memory')]},
              'native_operations': 0, 'in_window_PAS_requests': 0, 'ownership_qualified': False,
              'source_sha256': {p.name: sha(p.read_bytes()) for p in
                                (Path(__file__), Path(__file__).with_name('fdtree.py'))},
              'conclusion': 'Captured Kalama-family Android descriptions assign both exact spans to ADSP; inspected literal overlay reservations do not conflict. G139 remains the next prepared native diagnostic.',
              'limits': ['No current Android base/overlay selection or live bootloader-patched tree is observed.',
                         'Zero-size Demura regions are placeholders, not evidence that live Demura is disabled.',
                         'Android dynamic heaps describe allocation policy; they do not establish bare-metal or Windows ownership.',
                         'Resolving overlay targets and reserved literals is not a successful complete libfdt composition.',
                         'The saved native UEFI common FDT does not describe global DMA/display ownership.',
                         'Existing G116 disabled Demura observations and G109 installed-display analysis remain historical, not fresh-boot leases.',
                         'No address/cache eligibility, secure acceptance, payload copy, DSP start, GLINK or charging success is granted.']}
    if a.fdtget is not None:
        result['independent_libfdt_decode'] = independent_decode(a.fdtget, selections)
    a.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: result[k] for k in ('passed', 'Kalama_candidate_count', 'unique_Kalama_candidate_contents', 'native_operations', 'ownership_qualified')}))


if __name__ == '__main__':
    main()
