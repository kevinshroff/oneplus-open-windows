"""Compose original PIL, PILProxy and ChipInfo code with modeled external services.

No native firmware/SCM/NPA/MMIO operation occurs. ChipInfo initialization and
cached values are fixtures; the actual query, public callers and list code run.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import struct

import pefile
import unicorn
from unicorn import UC_HOOK_CODE, UC_HOOK_BLOCK, UC_HOOK_MEM_READ
from unicorn import UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC
from unicorn.arm64_const import *
from fdtree import Fdt

PIL, PROXY, CHIP, ARENA = 0x50000000, 0x60000000, 0x70000000, 0x30000000
ERR, NOTFOUND = 0x8000000000000007, 0x800000000000000E
PINS = {'PIL': '75dd928e1333044a9c7de275753e61b3c44ad5efb3051c62c3a12aa08f559716',
        'PILProxy': '45a4016c31bfe32bc6a7420ad63119ffa1bc1015cd168e4616e847ed077b0d13',
        'ChipInfo': '609c2e1d921b82faa03731a1fca728f660ae81dcb3796c8a9cf7023965052175'}
SUPPORT = '6f558a20256f771dde4953724e964197458e8d66de5ff7458eae8b095e505f37'
FDT_PIN = 'f0854f17171351b60254538941044e68cae283f1f6c9243faa14b71badbc2e29'
NODE = '/soc/pil/pil_proxy_vote/pil_proxy_vote_1'
REGS = [globals()['UC_ARM64_REG_X' + str(i)] for i in range(31)]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(ok, message):
    if not ok:
        raise AssertionError(message)


def load_image(path, name, base):
    raw = path.read_bytes()
    require(sha(raw) == PINS[name], name + ' image identity')
    pe = pefile.PE(data=raw)
    original = pe.get_memory_mapped_image()
    pe.relocate_image(base)
    return pe, original, pe.get_memory_mapped_image()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    for name in ('pil', 'proxy', 'chip', 'g140-source', 'config-dir', 'boot-fdt', 'proof-dir', 'output'):
        ap.add_argument('--' + name, type=Path, required=True)
    a = ap.parse_args()
    require(not a.output.exists(), 'refusing to replace existing evidence')
    require(sha(a.g140_source.read_bytes()) == SUPPORT, 'G140 support source identity')
    spec = importlib.util.spec_from_file_location('g140_bound_support', a.g140_source)
    g = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(g)
    require((g.PIL, g.ARENA) == (PIL, ARENA), 'support address contract')
    images = {'PIL': load_image(a.pil, 'PIL', PIL),
              'PILProxy': load_image(a.proxy, 'PILProxy', PROXY),
              'ChipInfo': load_image(a.chip, 'ChipInfo', CHIP)}
    for filename, name in [('proxy-binding-REA.json', 'PILProxy'), ('chip-binding-REA.json', 'ChipInfo'),
                           ('config-parser-REA.json', 'PILProxy'), ('allocation-REA.json', 'PILProxy')]:
        proof = json.loads((a.proof_dir / filename).read_text())
        for row in proof['records']:
            require(row['subject']['digest']['sha256'] == PINS[name], 'REA artifact identity')
            if row['operation'] == 'read_bytes':
                b = row['normalized_result']
                off = int(b['address'], 16)
                require(b['complete'] and images[name][1][off:off + b['returned_bytes']].hex() == b['bytes_hex'],
                        'REA bytes differ from original image')
    configs = {}
    for filename, digest in g.CFG_SHA.items():
        b = (a.config_dir / filename).read_bytes()
        require(sha(b) == digest and len(b) == 568, 'PIL config identity')
        configs['dtb' if 'DTB' in filename else 'main'] = b
    require(sha(a.boot_fdt.read_bytes()) == FDT_PIN, 'saved native boot FDT identity')
    fdt = Fdt.read(a.boot_fdt)
    require(fdt.cells(NODE, 'subsys_id') == [1] and fdt.strings(NODE, 'client_name') == ['PIL_ADSP']
            and fdt.cells(NODE, 'flag') == [3, 3], 'captured proxy configuration')

    class Bridge(g.Replay):
        def __init__(self, **options):
            self.options = options
            super().__init__(images['PIL'][2], images['PIL'][1], configs,
                             api_status=options.get('api_status', 0))
            self.stage_events = []
            self.registry, self.installations = {}, []
            self.npa, self.pool_allocations, self.freed = {}, {}, set()
            self.next_pool, self.creates = ARENA + 0x300000, 0
            self.chip_queries, self.cached_reads = [], 0
            self.proxy_events, self.blocks = [], {'PIL': 0, 'PILProxy': 0, 'ChipInfo': 0}
            self.timer, self.ssr_callback = None, None
            self.vote_cfg = PROXY + 0xC2A0
            self.proxy_bs, self.chip_bs = ARENA + 0x107000, ARENA + 0x108000
            self.devctx, self.drvctx, self.ssr_proto = ARENA + 0x109000, ARENA + 0x10A000, ARENA + 0x10B000
            self.dt_proto = ARENA + 0x10C000
            self.node_marker = b'G141-DT-node-model\0\0'
            require(len(self.node_marker) == 20, 'modeled DT node extent')
            self.dt_services = []
            self.config_getter_entries = self.zero_entries = 0
            self.tick = 0
            for name, base in [('PILProxy', PROXY), ('ChipInfo', CHIP)]:
                pe, original, image = images[name]
                n = (len(image) + 4095) & ~4095
                self.u.mem_map(base, n)
                self.u.mem_write(base, image)
                self.u.mem_protect(base, n, UC_PROT_READ | UC_PROT_EXEC)
                for section in pe.sections:
                    if section.Characteristics & 0x80000000:
                        self.u.mem_protect(base + section.VirtualAddress,
                                           (max(section.Misc_VirtualSize, section.SizeOfRawData) + 4095) & ~4095,
                                           UC_PROT_READ | UC_PROT_WRITE)
            self.q(PROXY + 0xC698, self.proxy_bs)
            self.q(CHIP + 0xD2E0, self.chip_bs)
            self.d(PROXY + 0xC168, int(options.get('ssr', False)))
            self.d(PROXY + 0xC294, 0)
            self.d(PROXY + 0xC290, 0)
            for off, target in [(0x40, 0x4C), (0x48, 0x50), (0x50, 0x10), (0x58, 0x14),
                                (0x70, 0x18), (0x140, 0x1C), (0x148, 0x20)]:
                self.q(self.proxy_bs + off, self.stub + target)
            self.q(self.chip_bs + 0x148, self.stub + 0x24)
            self.q(self.ssr_proto + 0x10, self.stub + 0x28)
            for off, target in ((0x30, 0x30), (0x90, 0x34), (0x98, 0x38),
                                (0xA0, 0x3C), (0xA8, 0x40), (0xB0, 0x44), (0xC0, 0x48)):
                self.q(self.dt_proto + off, self.stub + target)
            for off in (0x181C, 0x1B84, 0x2F3C, 0x3064, 0x79B8, 0x7AD0, 0x7B48,
                        0x7BC8, 0x7A68, 0x88B8, 0x2794, 0x439C, 0x4498, 0x4338, 0x3110, 0x10D8, 0x8264):
                self.u.hook_add(UC_HOOK_CODE, self.hook, begin=PROXY + off, end=PROXY + off)
            for off in (0x5C30, 0x5DB8, 0x5A8C, 0x5D9C, 0x17E8, 0x563C):
                self.u.hook_add(UC_HOOK_CODE, self.hook, begin=CHIP + off, end=CHIP + off)
            for off in range(0x10, 0x54, 4):
                self.u.hook_add(UC_HOOK_CODE, self.hook, begin=self.stub + off, end=self.stub + off)
            self.u.hook_add(UC_HOOK_MEM_READ, self.cache_read,
                            begin=CHIP + 0xD48C, end=CHIP + 0xD48F)
            for name, base in [('PIL', PIL), ('PILProxy', PROXY), ('ChipInfo', CHIP)]:
                self.u.hook_add(UC_HOOK_BLOCK, self.unchanged, user_data=(name, base),
                                begin=base, end=base + len(images[name][1]) - 1)
            require(self.rq(PROXY + 0xC1C0) == 0x10000
                    and self.rq(PROXY + 0xC1C8) == PROXY + 0x181C, 'ADSP interface relocation')
            require(self.rq(CHIP + 0xD0F0) == 0x10003
                    and self.rq(CHIP + 0xD168) == CHIP + 0x17E8, 'ChipInfo interface relocation')

        def d(self, at, value):
            self.u.mem_write(at, struct.pack('<I', value & 0xFFFFFFFF))

        def ascii(self, at):
            raw = bytes(self.u.mem_read(at, 256))
            require(b'\0' in raw, 'ASCII string bounds')
            return raw.split(b'\0', 1)[0].decode('ascii')

        def put_text(self, at, text):
            self.u.mem_write(at, text.encode('ascii') + b'\0')

        def pool_contains(self, at, size):
            return any(base <= at and at + size <= base + length and base not in self.freed
                       for base, length in self.pool_allocations.items())

        def config_snapshot(self):
            cfg = self.vote_cfg
            row = {'address': cfg, 'subsys_id': self.rd(cfg),
                   'record_bytes': bytes(self.u.mem_read(cfg, 96)).hex()}
            if not row['subsys_id']:
                return row
            rails, icbs, flags = (self.rd(cfg + off) for off in (0x10, 0x30, 0x48))
            require(rails <= 16 and icbs <= 16 and flags <= 16, 'constructed configuration counts')
            row.update(rail_count=rails, ICB_count=icbs, flag_count=flags,
                       flags_pointer_present=bool(self.rq(cfg + 0x50)))
            for name, off in [('client', 8), ('ICB_resource', 0x28)]:
                at = self.rq(cfg + off)
                if at:
                    require(self.pool_contains(at, 1), 'constructed string allocation')
                    row[name] = self.ascii(at)
            if rails:
                at = self.rq(cfg + 0x18)
                require(self.pool_contains(at, rails * 8), 'constructed rail array')
                row['rails'] = [self.ascii(self.rq(at + i * 8)) for i in range(rails)]
                at = self.rq(cfg + 0x20)
                require(self.pool_contains(at, rails * 4), 'constructed rail levels')
                row['raw_scalar_levels'] = [self.rd(at + i * 4) for i in range(rails)]
            if icbs:
                at = self.rq(cfg + 0x38)
                require(self.pool_contains(at, icbs * 8), 'constructed master/slave array')
                row['master_slave_pairs'] = [self.rd(at + i * 4) for i in range(icbs * 2)]
                at = self.rq(cfg + 0x40)
                require(self.pool_contains(at, icbs * 32), 'constructed ICB request allocation')
                row['request_bytes'] = bytes(self.u.mem_read(at, icbs * 32)).hex()
            if flags:
                at = self.rq(cfg + 0x50)
                require(self.pool_contains(at, flags * 4), 'constructed flag array')
                row['flags'] = [self.rd(at + i * 4) for i in range(flags)]
            return row

        def dt_service(self, pc, z):
            """Typed DT services are explicit models; the original caller builds its own structures."""
            if pc == self.stub + 0x30:
                require(self.ascii(z[1]) == NODE, 'original formatted DT path')
                self.dt_services.append({'operation': 'FindNode', 'path': NODE})
                if self.options.get('missing_config'):
                    self.ret(0xFFFFFFFF)
                else:
                    self.u.mem_write(z[0], self.node_marker)
                    self.ret()
                return
            require(bytes(self.u.mem_read(z[0], 20)) == self.node_marker, 'opaque DT node identity')
            key = self.ascii(z[1])
            require(key in fdt.nodes[NODE], 'captured DT property name')
            raw = fdt.nodes[NODE][key]
            names = {0x34: 'GetPropertySize', 0x38: 'GetRaw', 0x3C: 'GetUint32',
                     0x40: 'GetUint32Array', 0x44: 'GetUint32Slice', 0x48: 'GetUint64Array'}
            event = {'operation': names[pc - self.stub], 'key': key, 'property_bytes': len(raw)}
            self.dt_services.append(event)
            if pc == self.stub + 0x34:
                self.d(z[2], len(raw))
            elif pc == self.stub + 0x38:
                require(z[3] == len(raw), 'raw DT string byte count')
                self.u.mem_write(z[2], raw)
            elif pc == self.stub + 0x3C:
                require(len(raw) == 4, 'scalar DT property width')
                self.d(z[2], struct.unpack('>I', raw)[0])
            elif pc in (self.stub + 0x40, self.stub + 0x44):
                values = fdt.cells(NODE, key)
                if pc == self.stub + 0x40:
                    require(z[3] == len(raw), 'DT uint32 array byte count')
                else:
                    require(z[3] + z[4] <= len(values), 'DT uint32 slice bounds')
                    values = values[z[3]:z[3] + z[4]]
                self.u.mem_write(z[2], struct.pack('<' + 'I' * len(values), *values))
                event['native_uint32_fixture'] = values
            elif pc == self.stub + 0x48:
                require(z[3] == len(raw) and len(raw) % 8 == 0, 'DT uint64 array byte count')
                if self.options.get('dt_u64_error'):
                    self.ret(0xFFFFFFFF)
                    return
                values = list(struct.unpack('>' + 'Q' * (len(raw) // 8), raw))
                self.u.mem_write(z[2], struct.pack('<' + 'Q' * len(values), *values))
                event['native_uint64_fixture'] = values
            else:
                raise AssertionError('unmodeled typed DT service')
            self.ret()

        def unchanged(self, u, pc, size, metadata):
            name, base = metadata
            off = pc - base
            require(bytes(u.mem_read(pc, size)) == images[name][1][off:off + size], 'executed original code changed')
            self.blocks[name] += 1

        def cache_read(self, u, access, address, size, value, user):
            require(address == CHIP + 0xD48C and size == 4, 'cached ChipInfo read ABI')
            self.cached_reads += 1

        def install(self, chip=False):
            u = self.u
            if chip:
                require(u.reg_read(REGS[1]) == CHIP + 0xD078 and u.reg_read(REGS[2]) == CHIP + 0xD0F0
                        and u.reg_read(REGS[3]) == 0, 'ChipInfo publication arguments')
                values = [u.reg_read(REGS[1]), u.reg_read(REGS[2]), 0]
            else:
                sp = u.reg_read(UC_ARM64_REG_SP)
                values = [u.reg_read(r) for r in REGS[1:8]] + [self.rq(sp + i * 8) for i in range(10)]
                require(values[-1] == 0, 'proxy publication terminator')
                if self.options.get('proxy_install_error'):
                    self.ret(ERR)
                    return
            require(len(values[:-1]) % 2 == 0, 'publication pair count')
            for guid, interface in zip(values[:-1:2], values[1:-1:2]):
                raw_guid = bytes(u.mem_read(guid, 16)).hex()
                require(raw_guid not in self.registry, 'duplicate interface fixture')
                self.registry[raw_guid] = interface
                self.installations.append({'GUID': raw_guid, 'interface': interface,
                                           'revision': self.rq(interface), 'method': self.rq(interface + 8)})
            self.q(u.reg_read(REGS[0]), ARENA + 0x280000 + int(chip) * 256)
            self.ret()

        def hook(self, u, pc, size, unused):
            z = [u.reg_read(r) for r in REGS[:6]]
            p, c = pc - PROXY, pc - CHIP
            if pc == self.stub:
                guid = bytes(u.mem_read(z[0], 16)).hex()
                require(guid == configs['main'][0x104:0x114].hex(), 'PIL proxy GUID')
                value = self.registry.get(guid, 0)
                self.q(z[2], value)
                self.stage_events.append('LocateMainProxy')
                self.ret(0 if value else NOTFOUND)
            elif pc == self.stub + 4:
                raise AssertionError('The synthetic G140 proxy callback must not run')
            elif pc == self.stub + 0x10:
                require(z[:4] == [0x80000200, 8, PROXY + 0x14A0, self.vote_cfg], 'timer creation ABI')
                self.stage_events.append('CreateTimer_model')
                if self.options.get('timer_create_error'):
                    self.ret(ERR)
                    return
                self.timer = {'handle': ARENA + 0x250000, 'callback': z[2], 'context': z[3],
                              'scheduled': False, 'closed': False}
                self.q(z[4], self.timer['handle'])
                self.ret()
            elif pc == self.stub + 0x14:
                require(self.timer and z[:2] == [self.timer['handle'], 2], 'SetTimer ABI')
                self.stage_events.append('SetTimer_model')
                self.timer['ticks_100ns'] = z[2]
                self.timer['scheduled'] = not self.options.get('timer_set_error', False)
                self.ret(ERR if self.options.get('timer_set_error') else 0)
            elif pc == self.stub + 0x18:
                require(self.timer and z[0] == self.timer['handle'], 'CloseEvent ABI')
                self.timer['closed'] = True
                self.ret()
            elif pc == self.stub + 0x1C:
                raw_guid = bytes(u.mem_read(z[0], 16)).hex()
                chip_guid = bytes(u.mem_read(PROXY + 0xC0F8, 16)).hex()
                ssr_guid = bytes(u.mem_read(PROXY + 0xC108, 16)).hex()
                dt_guid = bytes(u.mem_read(PROXY + 0xC118, 16)).hex()
                require(raw_guid in (chip_guid, ssr_guid, dt_guid), 'proxy LocateProtocol GUID')
                value = (self.registry.get(chip_guid, 0) if raw_guid == chip_guid else
                         self.dt_proto if raw_guid == dt_guid else self.ssr_proto if self.options.get('ssr') else 0)
                self.q(z[2], value)
                self.stage_events.append('LocateChipInfo' if raw_guid == chip_guid else
                                         'LocateDT' if raw_guid == dt_guid else 'LocateSSR')
                self.ret(0 if value else NOTFOUND)
            elif pc in (self.stub + 0x20, self.stub + 0x24):
                self.install(chip=pc == self.stub + 0x24)
            elif pc == self.stub + 0x28:
                require(self.ascii(z[0]) == 'proxy_unvote' and z[1] == 1, 'SSR registration ABI')
                pair = (self.rq(z[2]), self.rq(z[2] + 8))
                require(pair == (PROXY + 0x14F4, self.vote_cfg), 'SSR callback/context')
                self.stage_events.append('RegisterSSR_model')
                if not self.options.get('ssr_register_error'):
                    self.ssr_callback = pair
                self.ret(ERR if self.options.get('ssr_register_error') else 0)
            elif self.stub + 0x30 <= pc <= self.stub + 0x48:
                self.dt_service(pc, z)
            elif pc == self.stub + 0x4C:
                require(z[0] == 4 and 0 < z[1] <= 4096, 'original AllocatePool ABI/bounds')
                at = self.next_pool
                self.next_pool = (at + z[1] + 63) & ~63
                self.pool_allocations[at] = z[1]
                # Original AllocateZeroPool wrappers must clear these poisoned bytes.
                u.mem_write(at, b'\xA5' * z[1])
                self.q(z[2], at)
                self.ret()
            elif pc == self.stub + 0x50:
                require(z[0] in self.pool_allocations and z[0] not in self.freed, 'original FreePool ABI')
                self.freed.add(z[0])
                u.mem_write(z[0], b'\xA5' * self.pool_allocations[z[0]])
                self.ret()
            elif c == 0x5C30:
                self.stage_events.append('Chip_DALSYS_environment_model')
                self.ret()
            elif c == 0x5DB8:
                require(z[0] == 0x200006F and z[1] == CHIP + 0xD2C8, 'DAL attach caller ABI')
                if self.options.get('chip_attach_error'):
                    self.ret(1)
                else:
                    u.reg_write(REGS[0], 0)
                    u.reg_write(REGS[1], z[0])
                    u.reg_write(REGS[2], z[1])
                    u.reg_write(UC_ARM64_REG_PC, CHIP + 0x56FC)
            elif c == 0x5A8C:
                require(z[:3] == [0x200006F, CHIP + 0xD1D8, CHIP + 0xD388], 'internal attach ABI')
                self.q(CHIP + 0xD398, self.devctx)
                self.q(self.devctx + 0x10, self.drvctx)
                self.d(self.devctx + 4, 0x200006F)
                for i in range(15):
                    self.d(CHIP + 0xD478 + i * 4, self.options.get('chip_flag', 0) if i == 5 else 0)
                self.stage_events.append('Chip_initialization_and_cached_flags_model')
                self.ret()
            elif c == 0x5D9C:
                require(z[:2] == [0x200006F, self.devctx + 0x18], 'property handle ABI')
                self.q(z[1], ARENA + 0x290000)
                self.ret(1 if self.options.get('chip_property_error') else 0)
            elif c == 0x17E8:
                require(z[0] == CHIP + 0xD0F0 and z[1] == 5 and ARENA <= z[2] < ARENA + 0x1000000,
                        'ChipInfo public query ABI')
                self.chip_queries.append(5)
            elif c == 0x563C:
                require(z[0] == 5 and ARENA <= z[1] < ARENA + 0x1000000, 'cached query thunk ABI')
            elif p == 0x181C:
                require(z[0] in (1, 2), 'main proxy event')
                require((z[0] == 1 and (self.rq(z[1]), self.rq(z[1] + 8)) == (self.base, self.size))
                        or (z[0] == 2 and z[1] == 0), 'actual PRE/POST arguments from PIL')
                self.proxy_events.append(z[0])
                self.stage_events.append('Proxy_PRE' if z[0] == 1 else 'Proxy_POST')
            elif p == 0x1B84:
                require(z[0] == 1, 'ADSP config lookup selector')
                self.config_getter_entries += 1
            elif p == 0x3110:
                require(self.ascii(z[2]) == '%a%d' and self.ascii(z[3]) == NODE[:-1]
                        and z[4] == 1, 'original configuration formatting ABI')
                text = (self.ascii(z[3]) + str(z[4])).encode('ascii') + b'\0'
                require(len(text) <= z[1] == 100, 'original format buffer bounds')
                u.mem_write(z[0], text)
                self.ret(len(text) - 1)
            elif p in (0x2F3C, 0x3064):
                pass  # Execute the original allocation/zeroing/free wrappers.
            elif p == 0x8264:
                require(z[0] in self.pool_allocations and z[1] == self.pool_allocations[z[0]],
                        'original zeroing extent')
                self.zero_entries += 1
            elif p == 0x79B8:
                self.creates += 1
                resource, client = self.ascii(z[0]), self.ascii(z[1])
                require(client == 'PIL_ADSP' and resource in fdt.strings(NODE, 'rail_names')
                        + fdt.strings(NODE, 'icb_name'), 'NPA resource/client identity')
                self.stage_events.append('NPA_create_' + resource)
                if self.creates == self.options.get('npa_create_error'):
                    self.ret(0)
                else:
                    handle = ARENA + 0x200000 + self.creates * 256
                    self.npa[handle] = {'resource': resource, 'client': client,
                                        'type': z[2], 'active': False, 'destroyed': False}
                    self.ret(handle)
            elif p in (0x7AD0, 0x7B48, 0x7BC8, 0x7A68):
                require(z[0] in self.npa and not self.npa[z[0]]['destroyed'], 'owned NPA handle')
                row = self.npa[z[0]]
                if p == 0x7AD0:
                    require(row['type'] == 64 and z[1] == 256, 'captured NPA scalar type/level')
                    row.update(active=True, scalar_level=z[1])
                elif p == 0x7B48:
                    expected = struct.pack('<IIQQQ', 4, 0, 100000000, 100000000, 0)
                    require(row['type'] == 1024 and z[1] == 8 and self.pool_contains(z[2], 32)
                            and bytes(u.mem_read(z[2], 32)) == expected, 'original typed ICB vector layout')
                    row.update(active=True, vector_elements=z[1], vector_pointer=z[2],
                               vector_bytes=bytes(u.mem_read(z[2], min(z[1] * 4, 256))).hex())
                elif p == 0x7BC8:
                    row['active'] = False
                else:
                    require(not row['active'], 'client destroyed before completion')
                    row['destroyed'] = True
                self.ret()
            elif p == 0x88B8:
                self.tick += 100
                self.ret(self.tick)
            elif p == 0x2794:
                self.ret(z[0])
            elif p == 0x4338:
                require(self.ascii(z[0]) in ('PilSubsysDbgCookieAddr', 'PilSubsysDbgCookieVal'), 'cookie config key')
                self.ret(NOTFOUND)
            elif p == 0x439C:
                self.ret()
            elif p in (0x4498, 0x10D8):
                raise AssertionError('original proxy assertion')
            else:
                if pc == PIL + 0x248C:
                    self.stage_events.append('SCM_AUTH_model')
                elif pc == PIL + 0x761C:
                    self.stage_events.append('Cache_clean_boundary_model')
                super().hook(u, pc, size, unused)

        def owned_nodes(self):
            head = PROXY + 0xC1F0
            current, previous, nodes = self.rq(head), head, []
            while current != head:
                require(len(nodes) < 8 and current in self.pool_allocations and current not in self.freed,
                        'original NPA list ownership/bounds')
                require(self.pool_allocations[current] == 40, 'original NPA node allocation extent')
                require(self.rq(current + 8) == previous, 'original NPA list backward link')
                handle = self.rq(current + 32)
                require(handle in self.npa and self.ascii(self.rq(current + 16)) == 'PIL_ADSP'
                        and self.ascii(self.rq(current + 24)) == self.npa[handle]['resource'], 'original NPA node contents')
                nodes.append({'address': current, 'handle': handle, 'resource': self.npa[handle]['resource']})
                previous, current = current, self.rq(current)
            require(self.rq(head + 8) == previous, 'original NPA list tail')
            return nodes

        def execute(self):
            chip_status = None
            if not self.options.get('chip_missing'):
                chip_status = self.invoke(CHIP + 0x18DC - PIL, ARENA + 0x280100, 0)
                if not self.options.get('chip_attach_error'):
                    require(chip_status == 0 and self.rq(CHIP + 0xD2C8) == CHIP + 0xD3A0
                            and self.rq(CHIP + 0xD3A8) == CHIP + 0xAFD0, 'actual ChipInfo attachment/publication')
            proxy_status = self.invoke(PROXY + 0x1AC0 - PIL)
            if not self.options.get('proxy_install_error'):
                require(self.registry[configs['main'][0x104:0x114].hex()] == PROXY + 0xC1C0,
                        'registered ADSP interface matches PIL config')
            status = self.invoke(0x373C, self.ctx)
            before = self.owned_nodes()
            before_state = {handle: dict(row) for handle, row in self.npa.items()}
            cached_probe = None
            if self.options.get('probe_partial_lookup'):
                calls_before = len(self.dt_services)
                pointer = self.invoke(PROXY + 0x1B84 - PIL, 1)
                cached_probe = {'returned': pointer, 'additional_DT_model_calls': len(self.dt_services) - calls_before,
                                'flags_pointer': self.rq(self.vote_cfg + 0x50)}
            if self.options.get('fire_timer'):
                require(self.timer and self.timer['scheduled'], 'no live modeled timer to deliver')
                self.invoke(self.timer['callback'] - PIL, self.timer['handle'], self.timer['context'])
            if self.options.get('fire_ssr'):
                require(self.ssr_callback is not None, 'no registered SSR fixture')
                self.invoke(self.ssr_callback[0] - PIL, 4, self.ssr_callback[1])
            after = self.owned_nodes()
            return {'options': self.options, 'PIL_auth_caller_status': hex(status),
                    'ChipInfo_initializer_status': None if chip_status is None else hex(chip_status),
                    'proxy_registration_return_raw': hex(proxy_status), 'interfaces': self.installations,
                    'SCM_auth_calls_modeled': self.auth_calls, 'original_proxy_events': self.proxy_events,
                    'original_ChipInfo_query_selectors': self.chip_queries,
                    'actual_cached_word_reads_in_replay': self.cached_reads,
                    'NPA_create_calls_modeled': self.creates, 'NPA_handles_modeled': self.npa,
                    'NPA_handles_before_callback': before_state,
                    'owned_nodes_before_callback': before, 'owned_nodes_after_callback': after,
                    'original_configuration': self.config_snapshot(), 'DT_service_models': self.dt_services,
                    'original_config_getter_entries': self.config_getter_entries,
                    'original_zero_wrapper_entries': self.zero_entries,
                    'pool_allocation_models': [{'address': at, 'bytes': size, 'freed': at in self.freed}
                                               for at, size in self.pool_allocations.items()],
                    'partial_cache_lookup_only_probe': cached_probe,
                    'timer_model': self.timer, 'SSR_registered_model': self.ssr_callback is not None,
                    'original_executed_blocks': self.blocks, 'stage_events': self.stage_events,
                    'PIL_boundary_events': self.events}

    cases = [
        ('timer-success', {'fire_timer': True}, 0, 1, 3, 0),
        ('SSR-success', {'ssr': True, 'fire_ssr': True}, 0, 1, 3, 0),
        ('ChipInfo-missing', {'chip_missing': True}, 5, 0, 0, 0),
        ('ChipInfo-attach-fails', {'chip_attach_error': True}, 5, 0, 0, 0),
        ('cached-selector5-nonzero', {'chip_flag': 1}, 5, 0, 0, 0),
        ('NPA-first-create-fails', {'npa_create_error': 1}, 5, 0, 0, 0),
        ('NPA-second-create-fails', {'npa_create_error': 2}, 5, 0, 1, 1),
        ('NPA-third-create-fails', {'npa_create_error': 3}, 5, 0, 2, 2),
        ('SCM-auth-fails-votes-retained', {'api_status': ERR}, 7, 1, 3, 3),
        ('POST-create-timer-fails', {'timer_create_error': True}, 5, 1, 3, 3),
        ('POST-set-timer-fails', {'timer_set_error': True}, 5, 1, 3, 3),
        ('SSR-registration-fails-timer-fallback', {'ssr': True, 'ssr_register_error': True, 'fire_timer': True}, 0, 1, 3, 0),
        ('proxy-publication-fails-caller-still-authenticates', {'proxy_install_error': True}, 0, 1, 0, 0),
        ('ChipInfo-property-error-is-ignored', {'chip_property_error': True, 'fire_timer': True}, 0, 1, 3, 0),
        ('DT-node-missing', {'missing_config': True}, 5, 0, 0, 0),
        ('DT-uint64-error-partial-cache', {'dt_u64_error': True, 'probe_partial_lookup': True}, 5, 0, 0, 0),
    ]
    rows = []
    for name, options, expected, calls, before, after in cases:
        run = Bridge(**options)
        row = run.execute()
        require((int(row['PIL_auth_caller_status'], 16), row['SCM_auth_calls_modeled'],
                 len(row['owned_nodes_before_callback']), len(row['owned_nodes_after_callback']))
                == (expected, calls, before, after), name + ' outcome')
        require(all(i == 5 for i in row['original_ChipInfo_query_selectors'])
                and len(row['original_ChipInfo_query_selectors']) == row['actual_cached_word_reads_in_replay'],
                name + ' cached-query coverage')
        require(row['original_zero_wrapper_entries'] == len(row['pool_allocation_models']),
                name + ' original zero-wrapper coverage')
        require(row['original_executed_blocks']['PIL'] > 0
                and row['original_executed_blocks']['PILProxy'] > 0, name + ' composed caller coverage')
        expected_queries = 0 if options.get('chip_missing') or options.get('chip_attach_error') \
            or options.get('proxy_install_error') else 1 + int(calls == 1 and expected != 7)
        require(len(row['original_ChipInfo_query_selectors']) == expected_queries, name + ' PRE/POST queries')
        expected_interfaces = (0 if options.get('chip_missing') or options.get('chip_attach_error') else 1) \
            + (0 if options.get('proxy_install_error') else 8)
        require(len(row['interfaces']) == expected_interfaces, name + ' original protocol publication')
        if before:
            cfg = row['original_configuration']
            require(cfg['subsys_id'] == 1 and cfg['client'] == 'PIL_ADSP'
                    and cfg['rails'] == fdt.strings(NODE, 'rail_names')
                    and cfg['raw_scalar_levels'] == [256, 256] and cfg['master_slave_pairs'] == [25, 0]
                    and cfg['flags'] == [3, 3]
                    and cfg['request_bytes'] == struct.pack('<IIQQQ', 4, 0, 100000000, 100000000, 0).hex(),
                    name + ' original parsed configuration')
            require(all(v['active'] and not v['destroyed'] for v in row['NPA_handles_before_callback'].values()),
                    name + ' voted resources before callback')
        if after:
            require(all(v['active'] and not v['destroyed'] for v in row['NPA_handles_modeled'].values()),
                    name + ' retained votes on error')
        elif before:
            require(all(not v['active'] and v['destroyed'] for v in row['NPA_handles_modeled'].values()),
                    name + ' callback resource cleanup')
        if row['timer_model'] and not options.get('timer_set_error'):
            require(row['timer_model']['ticks_100ns'] == 60000000000 and row['timer_model']['closed'],
                    name + ' original fallback timer conversion and close')
        if options.get('timer_set_error'):
            require(not row['timer_model']['scheduled'] and not row['timer_model']['closed'],
                    name + ' unscheduled event retained on SetTimer error')
        if options.get('fire_ssr'):
            require(row['SSR_registered_model'] and row['timer_model'] is None, name + ' SSR path')
        if options.get('probe_partial_lookup'):
            require(row['partial_cache_lookup_only_probe'] == {
                'returned': PROXY + 0xC2A0, 'additional_DT_model_calls': 0, 'flags_pointer': 0},
                name + ' original lookup returns partial cached record')
        order = row['stage_events']
        require(order.count('SCM_AUTH_model') == calls, name + ' secure boundary count')
        if calls and not options.get('proxy_install_error'):
            require(order.index('Cache_clean_boundary_model') < order.index('Proxy_PRE')
                    < order.index('SCM_AUTH_model'), name + ' clean/PRE/secure ordering')
            if expected != 7:
                require(order.index('SCM_AUTH_model') < order.index('Proxy_POST'), name + ' secure/POST ordering')
        if options.get('api_status'):
            require(2 not in row['original_proxy_events'] and row['timer_model'] is None,
                    name + ' secure error prevents POST and timer')
        row['case'] = name
        rows.append(row)
        print(json.dumps({'case': name, 'status': row['PIL_auth_caller_status'], 'owned_after': after}), flush=True)
    result = {'passed': True, 'cases': len(rows), 'image_sha256': PINS,
              'G140_support_source_sha256': SUPPORT, 'source_sha256': sha(Path(__file__).read_bytes()),
              'boot_FDT_sha256': FDT_PIN, 'Unicorn': unicorn.__version__, 'results': rows,
              'native_operations': 0, 'native_PAS_requests': 0, 'native_NPA_requests': 0,
              'limits': ['Actual original callers, interface publication arguments, ADSP callback, ChipInfo wrapper/attached DAL reader, typed configuration consumer, allocation/zero/free wrappers, NPA list/search/insert/remove and selected timer/SSR callbacks execute.',
                         'DALSYS environment, internal attachment/initialization, cached ChipInfo flags, property handles, typed DT services/conversions, pool allocation/free, NPA hardware operations, UEFI services and SCM returns are explicit fixtures.',
                         'The saved FDT bytes are observed; big-endian uint64 to native uint64 conversion is a DT-service model. The original consumer builds the 32-byte request from that fixture. The runtime DT backend is not established by the static EnvDxe publication table.',
                         'Native ChipInfo initialization/selector value, protocol dispatch, NPA resource state and resource-unit meanings are not established.',
                         'The already-qualified cache-clean boundary is modeled here; the G140 full-span cache walks are not rerun or counted as new cases.',
                         'No complete PIL image load, DSP instructions, GLINK, charging or Windows handoff occurs.',
                         'No new image/driver/native operation or eligibility grant; G139 remains unchanged as the next native test.']}
    a.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: result[k] for k in ('passed', 'cases', 'native_operations')}))


if __name__ == '__main__':
    main()
