"""Bind saved OnePlus DSDT/SMEM inputs to the original Windows GPU selector offline."""
from pathlib import Path
import argparse
import ast
import hashlib
import importlib.util
import json
import struct

import pefile
from unicorn import UC_HOOK_MEM_READ

G142_PIN = '9363d20a1c46bbab28f09d48d9d0a19ce695357c0be4491e139743e86698dd5d'
G108_PIN = 'd208c4dccf55eefc4722ef5b23f04aea3536c6bdfe0268495a16cdd82c4e48af'
DSDT_PIN = 'c8ef19940f424fce18a6e56580493629accb7c59a9ae495cc42c9445029f3e01'
CAPTURE_PIN = 'd810acb183fb3ba450ca39559ac4ac5e66d07f0743fc73308b135a0b30e5885c'
DECODED_PIN = '60f438c43e9ee1d01b6a1fd9df2b17130be05e227cbe7734eaefae08203d23e9'
SOC_PIN = '1ec617f124034c90071a56c8075b6dc504f2dde43b84678d19102decf60cb0d8'


def require(ok, message):
    if not ok:
        raise AssertionError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    for arg in ('image', 'g142-source', 'g108-source', 'dsdt', 'capture', 'decoded', 'proof', 'output'):
        ap.add_argument('--' + arg, type=Path, required=True)
    a = ap.parse_args()
    require(not a.output.exists(), 'refusing to replace prior evidence')
    for path, digest in [(a.g142_source, G142_PIN), (a.g108_source, G108_PIN), (a.dsdt, DSDT_PIN),
                         (a.capture, CAPTURE_PIN), (a.decoded, DECODED_PIN)]:
        require(sha(path.read_bytes()) == digest, 'input identity: ' + path.name)
    dsdt = a.dsdt.read_bytes()
    require(len(dsdt) == 576 and dsdt[:4] == b'DSDT' and sum(dsdt) % 256 == 0, 'saved native DSDT')
    marker = dsdt.index(b'SOSI')
    require(marker == 335 and dsdt.count(b'SOSI') == 1 and dsdt[marker-1] == 8
            and dsdt[marker+4] == 14, 'actual SOSI Name/QWord encoding')
    original_pointer = struct.unpack_from('<Q', dsdt, marker + 5)[0]
    require(original_pointer == 0xDEADBEEFFFFFFFFF, 'native DSDT SOSI sentinel')

    raw = a.capture.read_bytes()
    decoded = json.loads(a.decoded.read_text())
    require(len(raw) == 5243168 and raw[8:16] == b'OG135MR1', 'G135 raw header')
    region = next(r for r in decoded['regions'] if r['kind'] == 6 and r['host0'] == r['host1'] == 65534)
    require((int(region['address'], 16), region['offset'], region['bytes']) == (0x81D01000, 884736, 720896),
            'saved global heap bounds')
    off, n = 288 + region['offset'], region['bytes']
    heap = raw[off:off+n]
    require(heap == raw[off+n:off+2*n] and sha(heap) == region['first_sha256'] == region['second_sha256'],
            'G135 same-capture double sample')
    tree = ast.parse(a.g108_source.read_text())
    nodes = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'partition']
    require(len(nodes) == 1, 'qualified G108 decoder selection')
    ns = {'struct': struct, 'sha': sha}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(a.g108_source), 'exec'), ns)
    part = ns['partition'](heap, {'bytes': n, 'host0': 65534, 'host1': 65534, 'cacheline': 32})
    items = [r for r in part['items'] if r['id'] == 137]
    require(len(items) == 1 and len(part['items']) == 20, 'complete item137 selection')
    item = items[0]
    soc = item['data']
    physical = 0x81D01000 + item['relative_offset']
    require(physical == 0x81D08408 and len(soc) == 408 and sha(soc) == SOC_PIN, 'native SoCInfo item identity')
    fmt, soc_id, revision = struct.unpack_from('<III', soc)
    family = struct.unpack_from('<I', soc, 108)[0]
    require((fmt, soc_id, revision, family) == (18, 519, 0x20000, 127), 'selected nonserial native fields')

    spec = importlib.util.spec_from_file_location('g142_bound_support', a.g142_source)
    g = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(g)
    original = a.image.read_bytes()
    require(sha(original) == g.PIN, 'GPU image identity')
    pe = pefile.PE(data=original)
    image = pe.get_memory_mapped_image()
    imports = {i.name.decode(): i.address for lib in pe.DIRECTORY_ENTRY_IMPORT for i in lib.imports if i.name}
    for r in json.loads(a.proof.read_text())['records']:
        require(r['subject']['digest']['sha256'] == g.PIN, 'REA image identity')
        if r['operation'] == 'read_bytes':
            z = r['normalized_result']
            start = int(z['address'], 16) - g.BASE
            require(z['complete'] and image[start:start+z['returned_bytes']].hex() == z['bytes_hex'], 'REA byte witness')
    # Reuse the exact previously tested class, without running its CLI/case loop.
    parent = next(n for n in ast.parse(a.g142_source.read_text()).body if isinstance(n, ast.FunctionDef) and n.name == 'main')
    classes = [n for n in parent.body if isinstance(n, ast.ClassDef) and n.name == 'Replay']
    require(len(classes) == 1, 'bound G142 class selection')
    env = dict(g.__dict__, pe=pe, image=image, imports=imports)
    exec(compile(ast.Module(body=classes, type_ignores=[]), str(a.g142_source), 'exec'), env)
    Replay = env['Replay']

    class Bridge(Replay):
        def __init__(self, **options):
            super().__init__(family=0, revision=0, **options)
            self.route = options
            self.parent = g.ARENA + 0x400000
            self.map_requests, self.unmaps, self.queries = [], [], []
            self.views, self.soc_allocations, self.soc_frees = {}, {}, set()
            self.shared_leaf_returns, self.copy_result = 0, None
            self.record = bytearray(soc)
            if 'synthetic_family' in options:
                struct.pack_into('<I', self.record, 108, options['synthetic_family'])
            table = bytearray(dsdt)
            if options.get('corrected_pointer'):
                struct.pack_into('<Q', table, marker + 5, physical)
                table[9] = 0
                table[9] = -sum(table) % 256
            self.table = bytes(table)
            require(sum(self.table) % 256 == 0, 'counterfactual checksum')
            for name, off in [('ExAllocatePoolWithTag', 0x80), ('MmMapIoSpaceEx', 0x84),
                              ('MmUnmapIoSpace', 0x88), ('strcpy_s', 0x8C)]:
                self.q(imports[name], self.stub + off)
            for pc in [self.stub + off for off in (0x80, 0x84, 0x88, 0x8C)] + [
                    0x140586880, 0x140586758, 0x1400D1ABC]:
                self.u.hook_add(g.UC_HOOK_CODE, self.hook, begin=pc, end=pc)
            self.u.hook_add(UC_HOOK_MEM_READ, self.checked_read,
                            begin=g.ARENA + 0x600000, end=g.ARENA + 0x800000 - 1)

        def checked_read(self, u, access, at, size, value, unused):
            for base, length in self.soc_allocations.items():
                if base <= at < base + 4096:
                    require(base not in self.soc_frees and at + size <= base + length, 'DSDT read beyond owned allocation')
                    return
            for base, row in self.views.items():
                if base <= at < base + 4096:
                    require(row['active'] and at + size <= base + row['bytes'], 'SoCInfo read beyond modeled mapping')
                    return
            raise AssertionError('unowned SoC route memory read')

        def hook(self, u, pc, size, unused):
            z = [u.reg_read(r) for r in g.REGS[:6]]
            if pc == 0x140586880:
                self.ret(0xC0000001 if self.route.get('firmware_init_error') else 0)
            elif pc == 0x140586758:
                require(z[:2] == [0x41435049, 0x54445344], 'original ACPI/DSDT-only table query')
                self.queries.append({'buffer_null': z[2] == 0, 'buffer_bytes': z[3]})
                self.d(z[4], len(self.table))
                if not z[2]:
                    self.ret(0xC0000001 if self.route.get('table_probe_error') else 0xC0000023)
                else:
                    require(z[2] in self.soc_allocations and z[3] == len(self.table), 'owned firmware table buffer')
                    u.mem_write(z[2], self.table)
                    self.ret()
            elif pc == self.stub + 0x80:
                require(z[:3] == [1, len(self.table), 0x30696371], 'original table allocation ABI')
                if self.route.get('table_allocation_error'):
                    self.ret(0)
                else:
                    at = g.ARENA + 0x600000
                    require(not self.soc_allocations, 'unexpected repeated SoC table allocation')
                    self.soc_allocations[at] = z[1]
                    u.mem_write(at, b'\xA5' * 4096)
                    self.ret(at)
            elif pc == self.stub + 0x84:
                self.map_requests.append({'physical': hex(z[0]), 'bytes': z[1], 'protection': z[2]})
                require(z[2] == 2 and z[1] in (184, 256), 'original two-stage map ABI')
                if z[0] != physical or len(self.map_requests) == self.route.get('map_error'):
                    self.ret(0)
                else:
                    at = g.ARENA + 0x700000 + len(self.map_requests) * 0x10000
                    self.views[at] = {'bytes': z[1], 'active': True}
                    u.mem_write(at, bytes(self.record))
                    u.mem_protect(at, 4096, g.UC_PROT_READ)
                    self.ret(at)
            elif pc == self.stub + 0x88:
                require(z[0] in self.views and self.views[z[0]] == {'bytes': z[1], 'active': True}, 'original unmap ABI')
                self.views[z[0]]['active'] = False
                self.unmaps.append(z[1])
                self.ret()
            elif pc == self.stub + 0x8C:
                require(z[0] == 0x140316590 and z[1] == 32, 'original cached-name string copy')
                data = bytes(u.mem_read(z[2], z[1]))
                require(b'\0' in data, 'bounded string fixture')
                u.mem_write(z[0], data.split(b'\0', 1)[0] + b'\0')
                self.ret()
            elif pc == self.stub + 4 and z[0] in self.soc_allocations:
                require(z[0] not in self.soc_frees and z[1] == 0x30696371, 'original SoC table free ABI')
                self.soc_frees.add(z[0])
                self.ret()
            elif pc == 0x1401BE7E0 and z[:3] == [0x1403165C0, 0, 24]:
                u.mem_write(z[0], bytes(z[2]))
                self.ret(z[0])
            elif pc == 0x1401BB0A0 and u.reg_read(g.UC_ARM64_REG_X30) == 0x1401BB068:
                self.shared_leaf_returns += 1
                # Execute the original shared RET leaf on the copy-error branch.
            elif pc == 0x1400D1ABC:
                self.copy_result = z[0] & 0xFFFFFFFF
            else:
                super().hook(u, pc, size, unused)

        def source_route(self):
            stack, saved = self.registers(x19=self.parent)
            self.u.emu_start(0x140466B0C, 0x140466B5C, count=500000)
            require(self.u.reg_read(g.UC_ARM64_REG_PC) == 0x140466B5C
                    and self.u.reg_read(g.UC_ARM64_REG_SP) == stack
                    and self.u.reg_read(g.REGS[19]) == self.parent
                    and [self.u.reg_read(r) for r in g.REGS[21:30]] == saved[2:], 'bounded source fragment ABI')
            # Original caller copies the24-byte source tuple into the main factory config.
            self.u.reg_write(g.UC_ARM64_REG_SP, self.cfg - 16)
            self.u.reg_write(g.REGS[21], self.parent)
            self.u.emu_start(0x1404710CC, 0x1404710E8, count=100)
            require(self.u.reg_read(g.UC_ARM64_REG_PC) == 0x1404710E8
                    and bytes(self.u.mem_read(self.cfg + 0x290, 24)) == bytes(self.u.mem_read(self.parent + 0x4B40, 24)),
                    'original caller tuple copy')
            self.family = self.rd(self.parent + 0x4B40)
            self.revision = self.rd(self.parent + 0x4B48) >> 16
            before = len(self.queries), len(self.map_requests)
            if self.route.get('repeat_source'):
                self.u.reg_write(g.UC_ARM64_REG_SP, stack)
                self.u.reg_write(g.REGS[19], self.parent)
                self.u.emu_start(0x140466B0C, 0x140466B5C, count=500000)
                require(self.u.reg_read(g.UC_ARM64_REG_PC) == 0x140466B5C
                        and before == (len(self.queries), len(self.map_requests)), 'original ready cache prevents retry')
            require(all(not r['active'] for r in self.views.values()) and self.soc_frees == set(self.soc_allocations),
                    'SoC route model mappings/pool released')
            route = {'DSDT_sha256': sha(self.table), 'DSDT_is_original': self.table == dsdt,
                     'changed_DSDT_offsets': [i for i,(x,y) in enumerate(zip(dsdt, self.table)) if x != y],
                     'SOSI_pointer': hex(struct.unpack_from('<Q', self.table, marker + 5)[0]),
                     'table_queries_modeled': self.queries, 'maps_modeled': self.map_requests,
                     'unmap_lengths_modeled': self.unmaps, 'cache_ready': int(self.u.mem_read(0x140316560, 1)[0]),
                     'selected_source_fields': {'family': self.family, 'soc_id': self.rd(self.cfg + 0x294),
                                                'revision_raw': self.rd(self.cfg + 0x298)},
                     'ignored_copy_return': self.copy_result, 'original_shared_return_leaf_calls': self.shared_leaf_returns,
                     'copied_record_family_overridden_in_model': 'synthetic_family' in self.route}
            return route

    cases = [
        ('captured-DSDT-sentinel-map-failure-model', {'repeat_source': True}, 0, 0),
        ('counterfactual-SOSI-captured-SoCInfo', {'corrected_pointer': True, 'repeat_source': True}, 127, 0),
        ('synthetic-family88-control', {'corrected_pointer': True, 'synthetic_family': 0x88}, 0x88, 1),
        ('synthetic-family9a-control', {'corrected_pointer': True, 'synthetic_family': 0x9A}, 0x9A, 1),
        ('first-map-error', {'corrected_pointer': True, 'map_error': 1}, 0, 0),
        ('second-map-error', {'corrected_pointer': True, 'map_error': 2}, 0, 0),
        ('firmware-table-probe-error', {'table_probe_error': True}, 0, 0),
        ('firmware-table-allocation-error', {'table_allocation_error': True}, 0, 0),
        ('firmware-provider-init-error', {'firmware_init_error': True}, 0, 0),
    ]
    results = []
    for name, options, expected_family, expected_selection in cases:
        run = Bridge(**options)
        route = run.source_route()
        row = run.execute()
        require(route['selected_source_fields']['family'] == expected_family and route['cache_ready'] == 1
                and row['factory_status'] == '0x0' and row['selector_status'] == expected_selection,
                name + ' original source-to-selector outcome')
        if expected_family:
            require(route['selected_source_fields']['soc_id'] == 519
                    and route['selected_source_fields']['revision_raw'] == 0x20000
                    and route['ignored_copy_return'] == 0x22 and route['original_shared_return_leaf_calls'] == 1,
                    name + ' captured core fields and legacy bounded-copy refusal')
        require(row['selector_failure_logged'] == (expected_selection == 0), name + ' actual caller failure log')
        row.update(case=name, source_route=route)
        results.append(row)
        print(json.dumps({'case': name, 'source_family': hex(expected_family), 'selector': expected_selection}), flush=True)
    report = {'passed': True, 'cases': len(results), 'source_sha256': sha(Path(__file__).read_bytes()),
              'reused_G142_source_sha256': G142_PIN, 'reused_G108_decoder_sha256': G108_PIN,
              'driver_sha256': g.PIN, 'native_DSDT_sha256': DSDT_PIN, 'G135_capture_sha256': CAPTURE_PIN,
              'native_socinfo_item_sha256': SOC_PIN, 'native_item_physical_in_that_capture': hex(physical),
              'native_nonserial_fields': {'format': fmt, 'soc_id': soc_id, 'revision_raw': revision, 'family': family},
              'native_operations': 0, 'native_GPU_accesses': 0, 'results': results,
              'limits': [
                  'Saved native inputs feed original reader/cache/getters, two bounded caller fragments and the prior main factory/selector. The complete adapter or GPU initializer is not run.',
                  'The original DSDT contains a sentinel SOSI pointer. Returning map failure is an explicit service model, not a native attempt or a claim about the OS response to that address.',
                  'Corrected SOSI and family88/9a inputs are counterfactual/synthetic controls only; no DSDT, identity, profile or hardware value is modified natively.',
                  'Firmware-table services, pool/mapping, string copy and the reused G142 boundaries are models. Original memcpy_s error handling and its shared RET leaf execute; native runtime error-handler policy is unobserved.',
                  'The source path latches a failed lookup as ready. No installed GPU driver failure or current phone health is observed.',
                  'The optional SIDT tail and complete adapter setup are omitted. The first family/SoC/revision tuple is the qualified scope.',
                  'Only nonserial fields and hashes are exported; the raw SoCInfo record/capture remain private.',
                  'The real family127 is refused by this default selector even with a counterfactual corrected pointer. This does not rule out every driver/profile or establish that changing only a discriminator would work.',
                  'No G139 image/package change, native request or new eligibility grant occurs.']}
    a.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: report[k] for k in ('passed', 'cases', 'native_operations')}))


if __name__ == '__main__':
    main()
