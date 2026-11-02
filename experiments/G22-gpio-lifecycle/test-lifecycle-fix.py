#!/usr/bin/env python3
"""Execute the emitted ARM64 instructions with mocked framework/kernel calls.

These tests cover pointer/ABI/branch/zeroing/register behavior, not the real
Windows framework, interrupt delivery, or the physical GPIO controller.
"""
from pathlib import Path
import hashlib, json, struct, unittest
import pefile
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm64_const import *

ROOT = Path(__file__).resolve().parent
IMAGE = ROOT / 'private/G22-qcgpio-development.sys'
BASE = 0x140000000
ARENA = 0x30000000
CTX = ARENA + 0x1000
FUNCTIONS = ARENA + 0x10000
GLOBALS = ARENA + 0x11000
RECORDS = ARENA + 0x12000
STACK = ARENA + 0x3f000
BUFFER = ARENA + 0x60000
OWNER = 0x58000030
DEVICE = 0x58001000
STUB = 0x180000000
GUARD, DELETE, UNMAP, FREE, CREATE, END = [STUB + i * 0x100 for i in range(6)]

def setup():
    raw = IMAGE.read_bytes()
    receipt = json.loads(IMAGE.with_suffix('.json').read_text())
    assert hashlib.sha256(raw).hexdigest() == receipt['output_sha256']
    pe = pefile.PE(data=raw)
    u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    u.mem_map(BASE, 0x20000)
    u.mem_write(BASE, pe.get_memory_mapped_image())
    u.mem_map(ARENA, 0x100000)
    u.mem_map(STUB, 0x1000)
    u.mem_write(STUB, bytes.fromhex('c0035fd6') * 0x400)  # ret, hooked below.
    u.reg_write(UC_ARM64_REG_SP, STACK)
    put64(u, BASE + 0xd080, BASE + 0xd080)  # WPP disabled: self list head.
    put64(u, BASE + 0xd358, FUNCTIONS)
    put64(u, BASE + 0xd388, GLOBALS)
    put64(u, BASE + 0xc118, GUARD)
    put64(u, BASE + 0xc0d8, UNMAP)
    put64(u, BASE + 0xc0c8, FREE)
    put64(u, FUNCTIONS + 0x680, DELETE)
    put64(u, FUNCTIONS + 0x600, CREATE)
    return u

def put64(u, at, value):
    u.mem_write(at, struct.pack('<Q', value))

def get64(u, at):
    return struct.unpack('<Q', u.mem_read(at, 8))[0]

def get32(u, at):
    return struct.unpack('<I', u.mem_read(at, 4))[0]

def ret(u):
    u.reg_write(UC_ARM64_REG_PC, u.reg_read(UC_ARM64_REG_LR))

class LifecycleTests(unittest.TestCase):
    def test_prepare_retains_owner_and_preserves_parent(self):
        for success in [True, False]:
            with self.subTest(success=success):
                u = setup()
                u.reg_write(UC_ARM64_REG_X23, CTX)
                u.reg_write(UC_ARM64_REG_X26, DEVICE)
                u.reg_write(UC_ARM64_REG_X8, 56)
                u.mem_write(CTX + 0x14, struct.pack('<I', 384))
                u.mem_write(STACK + 0x90, b'LOCALOUT')
                calls = []
                def hook(u, address, size, opaque):
                    if address == GUARD:
                        self.assertEqual(u.reg_read(UC_ARM64_REG_X15), CREATE)
                        ret(u)
                    elif address == CREATE:
                        args = [u.reg_read(r) for r in [UC_ARM64_REG_X0, UC_ARM64_REG_X1,
                                UC_ARM64_REG_X2, UC_ARM64_REG_X3, UC_ARM64_REG_X4,
                                UC_ARM64_REG_X5, UC_ARM64_REG_X6]]
                        self.assertEqual(args, [GLOBALS, STACK + 0xe0, 0x200, 0x30697067,
                                                384, CTX + 0xe0, CTX + 0x30])
                        self.assertEqual(get32(u, args[1]), 56)
                        self.assertEqual(get64(u, args[1] + 0x20), DEVICE)
                        calls.append('create')
                        if success:
                            put64(u, args[5], OWNER)
                            put64(u, args[6], BUFFER)
                            u.mem_write(BUFFER, b'\xa5' * 384)
                        u.reg_write(UC_ARM64_REG_X0, 0 if success else 0xc000009a)
                        ret(u)
                    elif address == BASE + 0xa200:
                        self.assertTrue(success)
                        self.assertEqual([u.reg_read(r) for r in [UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2]], [BUFFER, 0, 384])
                        u.mem_write(BUFFER, bytes(384))
                        calls.append('zero')
                        ret(u)
                u.hook_add(UC_HOOK_CODE, hook)
                u.emu_start(BASE + 0x2a60, BASE + 0x2ac8, count=200)
                self.assertEqual(calls, ['create', 'zero'] if success else ['create'])
                self.assertEqual(get64(u, CTX + 0xe0), OWNER if success else 0)
                self.assertEqual(get64(u, CTX + 0x30), BUFFER if success else 0)
                self.assertEqual(bytes(u.mem_read(STACK + 0x90, 8)), b'LOCALOUT')
                if success:
                    self.assertEqual(bytes(u.mem_read(BUFFER, 384)), bytes(384))

    def test_full_release_preserves_registers_and_deletes_each_owner_once(self):
        u = setup()
        deletes, unmaps = [], []
        expected_owner = [None]
        def hook(u, address, size, opaque):
            if address == GUARD:
                self.assertEqual(u.reg_read(UC_ARM64_REG_X15), DELETE)
                ret(u)
            elif address == DELETE:
                args = (u.reg_read(UC_ARM64_REG_X0), u.reg_read(UC_ARM64_REG_X1))
                self.assertEqual(args, (GLOBALS, expected_owner[0]))
                self.assertNotIn(args[1], deletes)
                deletes.append(args[1])
                u.mem_write(BUFFER, b'\xdd' * 384)
                ret(u)
            elif address == UNMAP:
                unmaps.append((u.reg_read(UC_ARM64_REG_X0), u.reg_read(UC_ARM64_REG_X1)))
                ret(u)
            elif address == FREE:
                self.fail('raw pool free reached for WDF-owned buffer')
        u.hook_add(UC_HOOK_CODE, hook)
        for cycle in range(3):
            expected_owner[0] = OWNER + cycle * 0x100
            put64(u, CTX + 8, 0x40000000)
            u.mem_write(CTX + 0x10, struct.pack('<I', 0x1000000))
            put64(u, CTX + 0x30, BUFFER)
            put64(u, CTX + 0xe0, expected_owner[0])
            u.mem_write(BASE + 0xd664, struct.pack('<I', 2))
            put64(u, BASE + 0xd668, RECORDS)
            for i in range(2):
                put64(u, RECORDS + i * 48 + 0x10, 0x40001000 + i * 0x100)
                put64(u, RECORDS + i * 48 + 0x20, 0x40002000 + i * 0x100)
            regs = [UC_ARM64_REG_X19, UC_ARM64_REG_X20, UC_ARM64_REG_X21,
                    UC_ARM64_REG_X22, UC_ARM64_REG_X23, UC_ARM64_REG_X24,
                    UC_ARM64_REG_X25, UC_ARM64_REG_X26, UC_ARM64_REG_X27,
                    UC_ARM64_REG_X28, UC_ARM64_REG_X29]
            for i, reg in enumerate(regs):
                u.reg_write(reg, 0x71000000 + i * 0x100)
            saved = [u.reg_read(r) for r in regs]
            u.reg_write(UC_ARM64_REG_X0, DEVICE)
            u.reg_write(UC_ARM64_REG_X1, CTX)
            u.reg_write(UC_ARM64_REG_LR, END)
            u.emu_start(BASE + 0x2c30, END, count=500)
            self.assertEqual([u.reg_read(r) for r in regs], saved)
            self.assertEqual(u.reg_read(UC_ARM64_REG_SP), STACK)
            self.assertEqual(u.reg_read(UC_ARM64_REG_X0), 0)
            self.assertEqual(get64(u, CTX + 8), 0)
            self.assertEqual(get64(u, CTX + 0x30), 0)
            self.assertEqual(get64(u, CTX + 0xe0), 0)
        self.assertEqual(len(deletes), 3)
        self.assertEqual(len(unmaps), 15)
        self.assertEqual(unmaps[:5], [(0x40000000, 0x1000000), (0x40001000, 4),
                                    (0x40002000, 4), (0x40001100, 4), (0x40002100, 4)])

    def test_null_owner_clears_fields_without_free(self):
        u = setup()
        u.reg_write(UC_ARM64_REG_X19, CTX)
        put64(u, CTX + 0x30, BUFFER)
        def hook(u, address, size, opaque):
            if address in [GUARD, DELETE, FREE]:
                self.fail('no allocation owner, so no delete/free is valid')
        u.hook_add(UC_HOOK_CODE, hook)
        u.emu_start(BASE + 0x2cac, BASE + 0x2cfc, count=40)
        self.assertEqual(get64(u, CTX + 0x30), 0)
        self.assertEqual(get64(u, CTX + 0xe0), 0)
        self.assertEqual(u.reg_read(UC_ARM64_REG_X24), BASE + 0xc000)

    def test_pdc_exact_zeroing_and_volatile_pointer_restoration(self):
        for count in [2, 93]:
            with self.subTest(count=count):
                u = setup()
                u.reg_write(UC_ARM64_REG_X9, RECORDS)
                u.reg_write(UC_ARM64_REG_X23, BASE + 0xd660)
                u.reg_write(UC_ARM64_REG_X26, STACK)
                u.mem_write(BASE + 0xd664, struct.pack('<I', count))
                put64(u, STACK + 0x38, RECORDS)
                u.mem_write(RECORDS - 16, b'\x5a' * (count * 48 + 32))
                calls = []
                def hook(u, address, size, opaque):
                    if address == BASE + 0xa200:
                        args = [u.reg_read(r) for r in [UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2]]
                        self.assertEqual(args, [RECORDS, 0, count * 48])
                        u.mem_write(RECORDS, bytes(count * 48))
                        u.reg_write(UC_ARM64_REG_X9, 0xbad)
                        calls.append(args)
                        ret(u)
                u.hook_add(UC_HOOK_CODE, hook)
                u.emu_start(BASE + 0x8020, BASE + 0x8058, count=40)
                self.assertEqual(len(calls), 1)
                self.assertEqual(bytes(u.mem_read(RECORDS, count * 48)), bytes(count * 48))
                self.assertEqual(bytes(u.mem_read(RECORDS - 16, 16)), b'\x5a' * 16)
                self.assertEqual(bytes(u.mem_read(RECORDS + count * 48, 16)), b'\x5a' * 16)
                self.assertEqual(u.reg_read(UC_ARM64_REG_X9), RECORDS)

    def test_pdc_allocation_failure_takes_existing_error_branch(self):
        u = setup()
        u.reg_write(UC_ARM64_REG_X9, 0)
        seen = []
        def hook(u, address, size, opaque):
            seen.append(address)
        u.hook_add(UC_HOOK_CODE, hook)
        u.emu_start(BASE + 0x8020, BASE + 0x7d94, count=10)
        self.assertEqual(seen, [BASE + 0x8020])

if __name__ == '__main__':
    unittest.main(verbosity=2)
