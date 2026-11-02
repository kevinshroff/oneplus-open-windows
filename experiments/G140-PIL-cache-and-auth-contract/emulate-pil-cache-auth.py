"""Replay original PIL cache/authentication callers with explicit service models.

Cache maintenance, CTR_EL0, proxy callbacks, firmware loading and SCM results
are modeled. No firmware, cache instruction or secure call executes natively.
"""
from pathlib import Path
import argparse
import hashlib
import json
import struct

import pefile
import unicorn
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn import UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC
from unicorn.arm64_const import *

PIL, ARENA, STOP = 0x50000000, 0x30000000, 0x10000000
ERR, NOT_FOUND = 0x8000000000000007, 0x800000000000000E
PIL_SHA = '75dd928e1333044a9c7de275753e61b3c44ad5efb3051c62c3a12aa08f559716'
CFG_SHA = {
    'FULL_ADSP_DTB-config.bin': 'b0dbed167e1ad77a411c409beb7cdec9204822356a8245982884f63d6f924ea1',
    'FULL_ADSP-config.bin': '65913a28ec7082cacdaa1dca42719cdf1b748eac153d85c88cf3642961cfa992',
}
REGS = [globals()['UC_ARM64_REG_X' + str(i)] for i in range(31)]
SAVED = REGS[19:30]


def require(ok, message):
    if not ok:
        raise AssertionError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


class Replay:
    def __init__(self, image, original, configs, *, which='main', line=64,
                 full_cache=False, api_status=0, proxy_pre=0, proxy_post=0,
                 locate_status=0, null_proxy=False, orchestration=None):
        self.u = u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        self.line = line
        require(line in (32, 64, 128, 256), 'modeled CTR fixture')
        self.full_cache = full_cache
        self.api_status, self.proxy_pre, self.proxy_post = api_status, proxy_pre, proxy_post
        self.locate_status, self.null_proxy = locate_status, null_proxy
        self.events, self.cache_calls, self.primary_calls = [], [], []
        self.lines, self.first_line, self.last_line = 0, None, None
        self.clean_lines = self.invalidate_lines = self.barriers = self.isbs = 0
        self.auth_calls, self.proxy_calls, self.locate_calls = 0, [], 0
        self.orchestration = orchestration
        self.ctx, self.state, self.cfg = [ARENA + i for i in (0x1000, 0x2000, 0x3000)]
        self.dtb_cfg = ARENA + 0x5000
        self.bs, self.proxy, self.stub = ARENA + 0x10000, ARENA + 0x12000, ARENA + 0xF00000
        u.mem_map(PIL, (len(image) + 4095) & ~4095)
        u.mem_write(PIL, image)
        u.mem_map(ARENA, 0x1000000, UC_PROT_READ | UC_PROT_WRITE)
        u.mem_protect(self.stub, 4096, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)
        u.mem_map(STOP, 4096, UC_PROT_READ | UC_PROT_EXEC)
        u.reg_write(UC_ARM64_REG_CPACR_EL1, 3 << 20)
        u.mem_write(self.cfg, configs[which])
        u.mem_write(self.dtb_cfg, configs['dtb'])
        self.q(self.ctx, self.cfg)
        self.q(self.ctx + 8, self.state)
        self.base, self.size = ((0x9E980000, 0x80000) if which == 'dtb'
                                else (0x9EA00000, 0x4880000))
        self.q(self.state, self.base)
        self.q(self.state + 8, self.size)
        self.q(PIL + 0x1B168, self.bs)
        self.q(self.bs + 0x140, self.stub)
        self.q(self.proxy + 8, self.stub + 4)
        # Normal PE relocations affect pointer data, not these observed instructions.
        for off, size in ((0x761C, 100), (0x7680, 100), (0x373C, 280), (0x1C2C, 560),
                          (0x172C, 32), (0x49A0, 344), (0x10FCC, 32), (0x10FEC, 8),
                          (0x11104, 16), (0x11150, 16)):
            require(bytes(u.mem_read(PIL + off, size)) == original[off:off + size],
                    'observed code changed by relocation')
        # Protect the actual executed image after service/global fixtures are installed.
        u.mem_protect(PIL, (len(image) + 4095) & ~4095, UC_PROT_READ | UC_PROT_EXEC)
        for off in (0x761C, 0x7680, 0x10FEC, 0x11104, 0x1110C, 0x11150, 0x11158,
                    0x248C, 0x7B80, 0x7C7C, 0x10D8, 0x1838, 0x3F58, 0x10850):
            u.hook_add(UC_HOOK_CODE, self.hook, begin=PIL + off, end=PIL + off)
        for pc in (self.stub, self.stub + 4):
            u.hook_add(UC_HOOK_CODE, self.hook, begin=pc, end=pc)

    def q(self, at, value):
        self.u.mem_write(at, struct.pack('<Q', value))

    def rq(self, at):
        return struct.unpack('<Q', self.u.mem_read(at, 8))[0]

    def rd(self, at):
        return struct.unpack('<I', self.u.mem_read(at, 4))[0]

    def wide(self, at):
        data = bytes(self.u.mem_read(at, 128))
        end = next(i for i in range(0, len(data), 2) if data[i:i + 2] == b'\0\0')
        return data[:end].decode('utf-16le')

    def text(self, at, value):
        data = value.encode('utf-16le') + b'\0\0'
        require(len(data) <= 64, 'fixture string size')
        self.u.mem_write(at, data)

    def ret(self, value=0):
        u = self.u
        lr = u.reg_read(UC_ARM64_REG_X30)
        # UEFI/proxy/SCM service models may clobber all volatile argument registers.
        for i in range(1, 19):
            u.reg_write(REGS[i], 0xAA00000000000000 + i)
        u.reg_write(UC_ARM64_REG_X0, value)
        u.reg_write(UC_ARM64_REG_PC, lr)

    def hook(self, u, pc, size, unused):
        z = [u.reg_read(r) for r in REGS[:6]]
        off = pc - PIL
        if off in (0x761C, 0x7680):
            kind = 'clean_CVAC' if off == 0x761C else 'invalidate_IVAC'
            self.cache_calls.append({'kind': kind, 'base': z[0], 'bytes': z[1],
                                     'boundary_modeled': not self.full_cache})
            self.events.append(kind)
            if not self.full_cache:
                self.ret(z[0])
        elif off == 0x10FEC:
            u.reg_write(UC_ARM64_REG_X0, ((self.line.bit_length() - 1) - 2) << 16)
            u.reg_write(UC_ARM64_REG_PC, pc + 4)  # Model MRS CTR_EL0, execute original RET.
        elif off in (0x11104, 0x1110C):
            expected = ((self.cache_calls[0]['base'] & -self.line) if self.lines == 0
                        else self.last_line + self.line)
            require(z[0] == expected, 'nonmonotonic cache line address')
            if self.first_line is None:
                self.first_line = z[0]
            self.last_line = z[0]
            self.lines += 1
            if off == 0x1110C:
                self.clean_lines += 1
            else:
                self.invalidate_lines += 1
            u.reg_write(UC_ARM64_REG_PC, pc + 4)  # Cache effect modeled, original RET executes.
        elif off == 0x11150:
            self.barriers += 1
            self.events.append('DSB_SY')
        elif off == 0x11158:
            self.isbs += 1
            self.events.append('ISB')
        elif pc == self.stub:
            require(bytes(u.mem_read(z[0], 16)) == bytes(u.mem_read(self.cfg + 0x104, 16)),
                    'proxy LocateProtocol GUID')
            self.locate_calls += 1
            self.events.append('LocateProxy')
            self.q(z[2], 0 if self.locate_status or self.null_proxy else self.proxy)
            self.ret(self.locate_status)
        elif pc == self.stub + 4:
            event = z[0]
            require(event in (1, 2), 'unexpected proxy event')
            if event == 1:
                require(z[1] != 0 and (self.rq(z[1]), self.rq(z[1] + 8)) == (self.base, self.size),
                        'pre-auth range argument')
            else:
                require(z[1] == 0, 'post-auth event argument')
            self.proxy_calls.append(event)
            self.events.append('Proxy_PRE' if event == 1 else 'Proxy_POST')
            self.ret(self.proxy_pre if event == 1 else self.proxy_post)
        elif off == 0x248C:
            require(z[:4] == [self.ctx, 0x2000205, 1, self.rd(self.cfg + 0xEC)], 'auth caller ABI')
            self.auth_calls += 1
            self.events.append('SCM_AUTH_model')
            self.ret(self.api_status)
        elif off == 0x1838:
            require(self.orchestration is not None, 'unexpected primary loader boundary')
            self.primary_calls.append({'name': self.wide(z[0] + 12), 'image_id': self.rd(z[0] + 0xEC)})
            require(len(self.primary_calls) <= len(self.orchestration), 'unexpected repeat load')
            self.ret(self.orchestration[len(self.primary_calls) - 1])
        elif off == 0x3F58:
            name = self.wide(z[0])
            require(name == 'FULL_ADSP_DTB', 'unexpected recursive image lookup')
            self.ret(self.dtb_cfg)
        elif off in (0x7C7C, 0x10D8):
            raise AssertionError('OEM assertion/security failure at ' + hex(off))
        elif off in (0x7B80, 0x10850):
            self.ret()
        else:
            raise AssertionError('unmodeled service entry ' + hex(pc))

    def invoke(self, entry, *args):
        u = self.u
        stack = ARENA + 0xFF0000
        u.reg_write(UC_ARM64_REG_SP, stack)
        u.reg_write(UC_ARM64_REG_X30, STOP)
        for i in range(8):
            u.reg_write(REGS[i], args[i] if i < len(args) else 0)
        saved = [0xBB00000000000000 + i * 256 for i in range(len(SAVED))]
        for reg, value in zip(SAVED, saved):
            u.reg_write(reg, value)
        u.emu_start(PIL + entry, STOP, count=30000000)
        require(u.reg_read(UC_ARM64_REG_PC) == STOP, 'execution did not return within budget')
        require(u.reg_read(UC_ARM64_REG_SP) == stack, 'stack ABI changed')
        require([u.reg_read(r) for r in SAVED] == saved, 'callee-saved registers changed')
        return u.reg_read(UC_ARM64_REG_X0)

    def record(self, name, status):
        return {'case': name, 'status': hex(status), 'events': self.events,
                'cache_calls': self.cache_calls, 'CTR_line_bytes_fixture': self.line,
                'cache_line_instructions_modeled': self.lines, 'first_line': self.first_line,
                'last_line': self.last_line, 'CVAC': self.clean_lines, 'IVAC': self.invalidate_lines,
                'DSB_SY': self.barriers, 'ISB': self.isbs, 'SCM_auth_calls_modeled': self.auth_calls,
                'proxy_events_modeled': self.proxy_calls, 'LocateProxy_calls_modeled': self.locate_calls,
                'primary_loader_calls_modeled': self.primary_calls}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--image', type=Path, required=True)
    ap.add_argument('--config-dir', type=Path, required=True)
    ap.add_argument('--proof', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    a = ap.parse_args()
    require(not a.output.exists(), 'refusing to replace prior evidence')
    raw = a.image.read_bytes()
    require(sha(raw) == PIL_SHA, 'PIL identity')
    pe = pefile.PE(data=raw)
    original = pe.get_memory_mapped_image()
    pe.relocate_image(PIL)
    image = pe.get_memory_mapped_image()
    proof = json.loads(a.proof.read_text())
    for row in proof['byte_witnesses']:
        witness = row['normalized_result']
        require(row['subject']['digest']['sha256'] == PIL_SHA and witness['complete'], 'REA byte identity')
        off = int(witness['address'], 16)
        require(original[off:off + witness['returned_bytes']].hex() == witness['bytes_hex'], 'REA byte contradiction')
    configs = {}
    for name, digest in CFG_SHA.items():
        data = (a.config_dir / name).read_bytes()
        require(len(data) == 568 and sha(data) == digest, 'captured config identity')
        configs['dtb' if 'DTB' in name else 'main'] = data
    rows = []
    # Execute the full original cache loop through the authentication caller once
    # for each exact destination span; maintenance effects/CTR/proxy/SCM are models.
    for which in ('dtb', 'main'):
        run = Replay(image, original, configs, which=which, full_cache=True)
        print(json.dumps({'running': which + '-full-span-auth-caller'}), flush=True)
        status = run.invoke(0x373C, run.ctx)
        require(status == 0 and run.auth_calls == 1, 'full-span auth caller result')
        require(run.lines == run.size // 64 and run.clean_lines == run.lines
                and run.invalidate_lines == 0 and run.barriers == run.isbs == 1, 'full-span clean coverage')
        require(run.first_line == run.base and run.last_line == run.base + run.size - 64, 'full-span endpoints')
        require(run.events[:3] == ['clean_CVAC', 'DSB_SY', 'ISB'], 'cache barriers before auth/proxy')
        rows.append(run.record(which + '-full-span-auth-caller', status))
    # Boundary fixtures establish the actual wrappers' rounding and line-size use.
    for line, base, length in ((32, 0x32000003, 70), (64, 0x32000000, 0),
                               (64, 0x32000001, 0), (128, 0x32000040, 129),
                               (256, 0x32000000, 0x8000)):
        run = Replay(image, original, configs, line=line, full_cache=True)
        status = run.invoke(0x7680, base, length)
        start, end = base & -line, base + length
        count = max(0, (end - start + line - 1) // line)
        require(status == base and run.lines == count and run.invalidate_lines == count
                and run.clean_lines == 0 and run.barriers == run.isbs == 1, 'invalidate wrapper coverage')
        rows.append(run.record('invalidate-boundary-' + str(line) + '-' + hex(base) + '-' + hex(length), status))
    # The cache loop above is independently replayed; branch cases model that
    # boundary to avoid repeating millions of identical line operations.
    for name, kwargs, expected, calls, events in (
        ('main-success', {}, 0, 1, [1, 2]),
        ('main-pre-proxy-fails', {'proxy_pre': 1}, 5, 0, [1]),
        ('main-SCM-fails', {'api_status': ERR}, 7, 1, [1]),
        ('main-post-proxy-fails-after-SCM-success', {'proxy_post': 1}, 5, 1, [1, 2]),
        ('main-proxy-Locate-fails', {'locate_status': NOT_FOUND}, 0, 1, []),
        ('main-proxy-Locate-null', {'null_proxy': True}, 0, 1, []),
        ('dtb-no-proxy', {'which': 'dtb'}, 0, 1, []),
    ):
        run = Replay(image, original, configs, **kwargs)
        status = run.invoke(0x373C, run.ctx)
        require((status, run.auth_calls, run.proxy_calls) == (expected, calls, events), 'auth branch result')
        require(run.cache_calls == [{'kind': 'clean_CVAC', 'base': run.base, 'bytes': run.size,
                                     'boundary_modeled': True}], 'exact clean range call before branch')
        require(run.events[0] == 'clean_CVAC', 'clean precedes proxy handling')
        rows.append(run.record(name, status))
    # Current guard clears main preimage and admits only empty backup/post fields.
    for name, keep_pre, backup, post, returns, expected in (
        ('cleared-preimage-success', False, False, False, [0], 0),
        ('cleared-preimage-failure', False, False, False, [7], 0x8000000000000001),
        ('original-preimage-success', True, False, False, [0, 0], 0),
        ('original-preimage-failure', True, False, False, [7], 0x8000000000000001),
        ('controlled-backup-hazard', False, True, False, [7, 0], 0),
        ('controlled-post-image-after-failure-hazard', False, False, True, [7, 0], 0x8000000000000001),
    ):
        run = Replay(image, original, configs, orchestration=returns)
        if not keep_pre:
            run.u.mem_write(run.cfg + 0x174, bytes(64))
        if backup:
            run.text(run.cfg + 0x114, 'BACKUP')
        if post:
            run.text(run.cfg + 0x1B4, 'FULL_ADSP_DTB')
        status = run.invoke(0x172C, run.cfg)
        require(status == expected and len(run.primary_calls) == len(returns), 'orchestration outcome')
        require(run.auth_calls == 0, 'orchestration models must not reach real authentication caller')
        rows.append(run.record(name, status))
    result = {'passed': True, 'cases': len(rows), 'PIL_sha256': PIL_SHA,
              'config_sha256': CFG_SHA, 'REA_witness_sha256': sha(a.proof.read_bytes()),
              'source_sha256': sha(Path(__file__).read_bytes()), 'Unicorn': unicorn.__version__,
              'original_instruction_ranges_read_only': True, 'results': rows,
              'native_operations': 0, 'native_PAS_requests': 0, 'native_cache_operations': 0,
              'limits': ['CTR_EL0 values and cache/coherency effects are explicit models; native CTR was not captured.',
                         'PIL proxy callbacks, firmware loading, image lookup, logging and SCM results are service fixtures.',
                         'Only the two full-span cases execute the original cache loop through the original auth caller; branch cases model that independently replayed cache boundary.',
                         'No target data loads/stores execute; target spans are unmapped in the replay. Cache writeback effects are not simulated.',
                         'Proxy effects on clocks, resets, payload or memory policy are not established by caller replay.',
                         'Modeled SCM API success is not live secure acceptance, DSP readiness, GLINK, charging or ownership qualification.',
                         'The native G139 image/guards/release remain unchanged and unbooted.']}
    a.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: result[k] for k in ('passed', 'cases', 'native_operations')}))


if __name__ == '__main__':
    main()
