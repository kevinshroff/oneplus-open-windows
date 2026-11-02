"""Replay the original main Gen7 factory/config selector, with external services modeled.

The complete hardware initializer, firmware loading and Windows start do not run.
"""
from pathlib import Path
import argparse
import hashlib
import json
import struct

import pefile
import unicorn
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_BLOCK
from unicorn import UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC
from unicorn.arm64_const import *

BASE, ARENA, STOP = 0x140000000, 0x30000000, 0x10000000
PIN = 'cb127c49b4a61d108a1b6ae1962ef86704373e0bf81c6b5178d413fbad76f01d'
REGS = [globals()['UC_ARM64_REG_X' + str(i)] for i in range(31)]


def require(ok, message):
    if not ok:
        raise AssertionError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    for arg in ('image', 'proof', 'output'):
        ap.add_argument('--' + arg, type=Path, required=True)
    a = ap.parse_args()
    require(not a.output.exists(), 'refusing to replace prior evidence')
    raw = a.image.read_bytes()
    require(sha(raw) == PIN, 'driver identity')
    pe = pefile.PE(data=raw)
    require(pe.OPTIONAL_HEADER.ImageBase == BASE, 'driver preferred base')
    image = pe.get_memory_mapped_image()
    proof = json.loads(a.proof.read_text())
    for record in proof['records']:
        require(record['subject']['digest']['sha256'] == PIN, 'REA driver identity')
        if record['operation'] == 'read_bytes':
            n = record['normalized_result']
            off = int(n['address'], 16) - BASE
            require(n['complete'] and image[off:off + n['returned_bytes']].hex() == n['bytes_hex'],
                    'REA original byte witness')
    imports = {}
    for library in pe.DIRECTORY_ENTRY_IMPORT:
        for row in library.imports:
            if row.name:
                imports[row.name.decode()] = row.address

    class Replay:
        def __init__(self, family=0x88, revision=1, **options):
            self.family, self.revision, self.options = family, revision, options
            self.u = u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
            n = (len(image) + 4095) & ~4095
            u.mem_map(BASE, n)
            u.mem_write(BASE, image)
            u.mem_map(ARENA, 0x1000000, UC_PROT_READ | UC_PROT_WRITE)
            u.mem_map(STOP, 4096, UC_PROT_READ | UC_PROT_EXEC)
            self.stub = ARENA + 0xF00000
            u.mem_protect(self.stub, 4096, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)
            u.reg_write(UC_ARM64_REG_CPACR_EL1, 3 << 20)
            self.cfg, self.context_out, self.methods_out, self.flags_out = [ARENA + i for i in (0x1000, 0x2000, 0x3000, 0x4000)]
            self.pool, self.freed, self.alloc_count, self.blocks = {}, set(), 0, 0
            self.registry_calls, self.logs, self.constructors = [], [], []
            self.selector_status, self.selector_calls = None, 0
            self.q(self.cfg, ARENA + 0x20000)
            self.q(self.cfg + 0x130, self.stub + 8)
            self.d(self.cfg + 0x290, family)
            self.d(self.cfg + 0x298, revision << 16)
            self.u.mem_write(self.cfg + 0x280, options.get('class_name', 'Adreno7X').encode() + b'\0')
            self.q(imports['ExAllocatePool2'], self.stub)
            self.q(imports['ExFreePoolWithTag'], self.stub + 4)
            # No instruction bytes or original pointer tables are patched.
            u.mem_protect(BASE, n, UC_PROT_READ | UC_PROT_EXEC)
            for section in pe.sections:
                if section.Characteristics & 0x80000000:
                    u.mem_protect(BASE + section.VirtualAddress,
                                  (max(section.Misc_VirtualSize, section.SizeOfRawData) + 4095) & ~4095,
                                  UC_PROT_READ | UC_PROT_WRITE)
            for pc in [self.stub, self.stub + 4, self.stub + 8,
                       0x1401BE7E0, 0x1401BF680, 0x1401BB0A0, 0x14000AC70,
                       0x140010A68, 0x140010AB0, 0x140010AF8, 0x14049F370,
                       0x14049C288, 0x14049CB10]:
                u.hook_add(UC_HOOK_CODE, self.hook, begin=pc, end=pc)
            u.hook_add(UC_HOOK_BLOCK, self.unchanged, begin=BASE, end=BASE + len(image) - 1)

        def q(self, at, value):
            self.u.mem_write(at, struct.pack('<Q', value))

        def d(self, at, value):
            self.u.mem_write(at, struct.pack('<I', value & 0xFFFFFFFF))

        def rq(self, at):
            return struct.unpack('<Q', self.u.mem_read(at, 8))[0]

        def rd(self, at):
            return struct.unpack('<I', self.u.mem_read(at, 4))[0]

        def ascii(self, at):
            return bytes(self.u.mem_read(at, 256)).split(b'\0', 1)[0].decode('ascii')

        def ret(self, value=0):
            lr = self.u.reg_read(UC_ARM64_REG_X30)
            for i in range(1, 19):
                self.u.reg_write(REGS[i], 0xAA00000000000000 + i)
            self.u.reg_write(REGS[0], value)
            self.u.reg_write(UC_ARM64_REG_PC, lr)

        def unchanged(self, u, pc, size, unused):
            off = pc - BASE
            require(bytes(u.mem_read(pc, size)) == image[off:off + size], 'executed original code changed')
            self.blocks += 1

        def hook(self, u, pc, size, unused):
            z = [u.reg_read(r) for r in REGS[:6]]
            if pc == self.stub:
                self.alloc_count += 1
                require(z[0] == 0x40 and z[1] in (0x2198, 0xE8) and z[2] == 0x48584471,
                        'original main-factory allocation ABI')
                if self.alloc_count == self.options.get('allocation_error'):
                    self.ret(0)
                else:
                    at = ARENA + 0x100000 + self.alloc_count * 0x10000
                    self.pool[at] = z[1]
                    u.mem_write(at, bytes(z[1]))  # Explicit zeroed pool fixture.
                    self.ret(at)
            elif pc == self.stub + 4:
                require(z[0] in self.pool and z[0] not in self.freed and z[1] == 0x48584471, 'owned pool free')
                self.freed.add(z[0])
                u.mem_write(z[0], b'\xA5' * self.pool[z[0]])
                self.ret()
            elif pc == self.stub + 8:
                require(z[0] == ARENA + 0x20000 and ARENA <= z[3] < ARENA + 0x1000000,
                        'registry callback ABI')
                key = self.ascii(z[2])
                require(key in ('VertexFetchInterruptsActive', 'FlushTLBOnEverySubmit', 'DisableCB',
                                'SleepMode', 'DisableICG', 'DisableGmuACD', 'EnableFallbackToDisableSecureMode',
                                'DisableCPCrashDump', 'Preemption', 'PreemptionCounter', 'UcheClientId',
                                'ClearPageFaultOnReset', 'EnableDynPwrLog', 'EnableLkgPwrLog', 'PwrBdgtMode',
                                'PwrBdgtCharModeBufSize', 'PwrBdgtSamplePeriod', 'StallOnFault', 'DisableLpac'),
                        'selected original registry query')
                self.registry_calls.append(key)
                self.d(z[3], int(key == 'DisableLpac' and self.options.get('disable_lpac', False)))
                self.ret(0 if key == 'DisableLpac' and self.options.get('disable_lpac') else 0xC0000034)
            elif pc == 0x1401BE7E0:
                require(z[:3] == [self.methods_out, 0, 0x148], 'main factory memset')
                u.mem_write(z[0], bytes(z[2]))
                self.ret(z[0])
            elif pc == 0x1401BF680:
                require(z[2] == 0x278, 'main factory interface copy extent')
                u.mem_write(z[0], bytes(u.mem_read(z[1], z[2])))
                self.ret(z[0])
            elif pc == 0x1401BB0A0:
                require(u.reg_read(REGS[15]) in (0x14049F370, self.stub + 8), 'CFG fixture target')
                # This guard boundary preserves argument registers and callable X15.
                u.reg_write(UC_ARM64_REG_PC, u.reg_read(UC_ARM64_REG_X30))
            elif pc == 0x14000AC70:
                self.ret(0)  # Optional external microcode-file route disabled in this fixture.
            elif pc in (0x140010A68, 0x140010AB0, 0x140010AF8):
                self.logs.append({'routine': hex(pc), 'tag': hex(z[0]), 'arg1': hex(z[1])})
                self.ret()
            elif pc == 0x14049F370:
                self.constructors.append(pc)
            elif pc == 0x14049C288:
                require(z[0] == self.rq(self.context_out), 'original selection caller context')
                self.selector_calls += 1
            elif pc == 0x14049CB10:
                self.selector_status = z[0] & 0xFFFFFFFF
            else:
                raise AssertionError('unmodeled boundary')

        def registers(self, x19=None):
            stack = ARENA + 0xFF0000
            self.u.reg_write(UC_ARM64_REG_SP, stack)
            saved = [0xBB00000000000000 + i * 256 for i in range(11)]
            if x19 is not None:
                saved[0] = x19
            for reg, value in zip(REGS[19:30], saved):
                self.u.reg_write(reg, value)
            return stack, saved

        def execute(self):
            stack, saved = self.registers()
            args = [self.cfg, self.context_out, self.methods_out, self.flags_out]
            if self.options.get('null_config'):
                args[0] = 0
            for reg, value in zip(REGS, args):
                self.u.reg_write(reg, value)
            self.u.reg_write(UC_ARM64_REG_X30, STOP)
            self.u.emu_start(0x140486AA0, STOP, count=500000)
            require(self.u.reg_read(UC_ARM64_REG_PC) == STOP and self.u.reg_read(UC_ARM64_REG_SP) == stack
                    and [self.u.reg_read(r) for r in REGS[19:30]] == saved, 'main-factory return/ABI')
            status = self.u.reg_read(REGS[0]) & 0xFFFFFFFF
            ctx = self.rq(self.context_out)
            result = {'factory_status': hex(status), 'context': ctx, 'family_fixture': hex(self.family),
                      'revision_fixture': self.revision, 'options': self.options}
            if status == 0:
                require(ctx in self.pool and self.rq(0x1403164A0) == ctx and self.rd(ctx + 0x80) == 0xDEADBEEF
                        and self.rq(self.methods_out) == 0x140482BE0
                        and self.rq(ctx + 0x1238) == 0x14049C860 and self.rd(ctx + 0x11E0) == self.family,
                        'actual main factory/Gen7 binding')
                require(self.rd(ctx + 0x1144) == 0xFFFFFFFF, 'original factory profile sentinel')
                if 'profile_override' in self.options:
                    self.d(ctx + 0x1144, self.options['profile_override'])
                stack, saved = self.registers(x19=ctx)
                # Original bounded initialization fragment calls the original selector.
                # Stop at its common continuation, before the rest of initialization.
                self.u.emu_start(0x14049CB08, 0x14049CB30, count=500000)
                require(self.u.reg_read(UC_ARM64_REG_PC) == 0x14049CB30
                        and self.u.reg_read(UC_ARM64_REG_SP) == stack
                        and [self.u.reg_read(r) for r in REGS[19:30]] == saved
                        and self.selector_calls == 1, 'original selector fragment return/ABI/bounds')
                pointer, count = self.rq(ctx + 0x1200), self.rd(ctx + 0x11F8)
                firmware = None
                if pointer:
                    require(BASE <= pointer < BASE + len(image) and count in (0x4E3C, 0x4DEC), 'embedded microcode bounds')
                    data = bytes(self.u.mem_read(pointer, 64))
                    firmware = {'address': hex(pointer), 'raw_count11f8': count,
                                'prefix_bytes': len(data), 'prefix_sha256': sha(data)}
                result.update(selector_status=self.selector_status,
                              original_initializer_reached_common_continuation=True,
                              selector_failure_logged=any(r['tag'] == '0x1437' for r in self.logs),
                              raw_profile1144=hex(self.rd(ctx + 0x1144)), raw_word114c=hex(self.rd(ctx + 0x114C)),
                              raw_word1150=hex(self.rd(ctx + 0x1150)), flags1110=hex(self.rd(ctx + 0x1110)),
                              embedded_microcode=firmware, raw_word115c=hex(self.rd(ctx + 0x115C)))
            else:
                require(ctx == 0 and self.rq(0x1403164A0) == 0 and self.freed == set(self.pool),
                        'factory error releases owned allocations and global')
            result.update(original_Gen7_constructors=self.constructors, registry_models=self.registry_calls,
                          logs_modeled=self.logs, allocations_modeled=len(self.pool), frees_modeled=len(self.freed),
                          original_executed_blocks=self.blocks)
            return result

    cases = []
    for family in (0x88, 0x9A):
        for rev in (0, 1, 2):
            cases.append(('default-' + hex(family) + '-rev' + str(rev), family, rev, {}, 0, 1))
    for family in (0, 1, 0x7F, 0x87, 0x89, 0x99, 0x9B, 0xFFFFFFFF):
        cases.append(('unrecognized-family-' + hex(family), family, 1, {}, 0, 0))
    cases.extend([
        ('registry-disable-lpac', 0x88, 1, {'disable_lpac': True}, 0, 1),
        ('factory-first-allocation-fails', 0x88, 1, {'allocation_error': 1}, 0xC0000017, None),
        ('factory-second-allocation-fails', 0x88, 1, {'allocation_error': 2}, 0xC0000017, None),
        ('factory-unknown-class', 0x88, 1, {'class_name': 'Unknown'}, 0xC000000E, None),
        ('factory-null-config', 0x88, 1, {'null_config': True}, 0xC000000D, None),
        ('negative-profile-override-mismatched-family', 0, 1, {'profile_override': 0x50C000}, 0, 1),
        ('negative-profile-override-mismatched-profile', 0x88, 1, {'profile_override': 0x30C000}, 0, 1),
        ('negative-unrecognized-profile-override', 0x88, 1, {'profile_override': 0xDEADBEEF}, 0, 0),
    ])
    results = []
    for name, family, revision, options, factory_status, selected in cases:
        row = Replay(family, revision, **options).execute()
        require(int(row['factory_status'], 16) == factory_status, name + ' factory status')
        if selected is not None:
            require(row['selector_status'] == selected and row['selector_failure_logged'] == (selected == 0),
                    name + ' selected branch and caller error propagation')
            require(row['original_Gen7_constructors'] == [0x14049F370], name + ' actual main constructor')
            if not options.get('profile_override') and selected:
                require(row['embedded_microcode'] is not None and row['raw_word115c'] == '0x185'
                        and row['raw_profile1144'] == hex(0x50C000 if family == 0x88 else 0x30C000),
                        name + ' default family-specific microcode selection')
            if family == 0 and options.get('profile_override'):
                require(row['embedded_microcode'] is None, name + ' status success is not a complete profile')
            if options.get('disable_lpac'):
                require(int(row['flags1110'], 16) & 0x20 == 0, name + ' modeled registry effect')
        row['case'] = name
        results.append(row)
        print(json.dumps({'case': name, 'factory': row['factory_status'], 'selected': row.get('selector_status')}), flush=True)
    result = {'passed': True, 'cases': len(results), 'driver_sha256': PIN,
              'source_sha256': sha(Path(__file__).read_bytes()), 'Unicorn': unicorn.__version__,
              'native_operations': 0, 'native_GPU_accesses': 0, 'results': results,
              'limits': [
                  'Original main factory, main Gen7 constructor/settings, configuration selector and bounded initialization callsite run. This is not complete hardware initialization or Windows StartDevice.',
                  'Pool, registry, logging, memcpy/memset, transparent CFG validation and optional external microcode-file availability are explicit fixtures.',
                  'Raw family codes are opaque configuration discriminators copied from caller+0x290 into context+0x11e0. Their namespace, SoC names and the phone native value are not established here; no firmware ChipInfo namespace or GPU marketing name is equated to them.',
                  'Profile overrides are contradictory negative fixtures, not patches or a proposed bypass. A selector success alone can leave no microcode and is not support evidence.',
                  'The original initializer logs selection failure and reaches its next block; later behavior is not executed or inferred.',
                  'A fixed64-byte prefix at each selected embedded-data pointer is hashed. The raw count field is retained without inferring its unit or parsing a complete firmware image. Nothing is sent to a GPU or qualified as A740 firmware.',
                  'No driver installation, INF/ACPI change, GPU power/MMIO/DMA/interrupt/firmware request or G139 change occurs.']}
    a.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: result[k] for k in ('passed', 'cases', 'native_operations')}))


if __name__ == '__main__':
    main()
