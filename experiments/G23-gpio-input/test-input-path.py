"""Exercise the exact G22 ARM64 ConnectIoPins and ReadGpioPins callbacks.

Emulated registers are evidence about emitted instructions, not physical
EGPIO ownership, interrupt delivery, or Windows' operation-region handling.
"""
from pathlib import Path
import hashlib, importlib.util, json, struct
from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn.arm64_const import *

W = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('g22_tests', W.parent / 'gpio-G22/test-lifecycle-fix.py')
g = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)
MMIO = 0x40000000
PARAM = g.ARENA + 0x70000
PINS = PARAM + 0x100
OUT = PARAM + 0x200
contract = json.loads((W.parent / 'gpio-G21/controller-table-candidate.json').read_text())
results = []
for pin, before in [(25, 1), (174, 0x801)]:
    for level in [0, 1]:
        u = g.setup()
        u.mem_map(MMIO, 0x1000000)
        g.put64(u, g.CTX + 8, MMIO)
        g.put64(u, g.CTX + 0x30, g.BUFFER)
        u.mem_write(g.BUFFER, bytes(384))
        u.mem_write(g.CTX + 0x14, struct.pack('<I', 384))
        u.mem_write(g.CTX + 0x18, struct.pack('<I', 210))
        u.mem_write(g.CTX + 0x24, struct.pack('<I', 4096))
        for f in contract['selector4_values']:
            u.mem_write(g.CTX + int(f['context_offset'], 16), struct.pack('<I', f['value']))
        reg = MMIO + 0x100000 + pin * 4096
        u.mem_write(reg, struct.pack('<IIII', before, 2 | level, 0xe2, 0))
        u.mem_write(PARAM, bytes(64))
        u.mem_write(PARAM, struct.pack('<H', pin // 64))
        g.put64(u, PARAM + 8, PINS)
        u.mem_write(PARAM + 0x10, struct.pack('<H', 1))
        u.mem_write(PARAM + 0x14, struct.pack('<I', 1))  # ConnectModeInput
        u.mem_write(PINS, struct.pack('<H', pin % 64))
        writes = []
        def memory_write(uc, access, address, size, value, opaque):
            if MMIO <= address < MMIO + 0x1000000:
                writes.append({'address': hex(address), 'bytes': size, 'value': hex(value)})
        u.hook_add(UC_HOOK_MEM_WRITE, memory_write)
        def call(rva):
            u.reg_write(UC_ARM64_REG_X0, g.CTX)
            u.reg_write(UC_ARM64_REG_X1, PARAM)
            u.reg_write(UC_ARM64_REG_LR, g.END)
            u.emu_start(g.BASE + rva, g.END, count=1200)
            assert u.reg_read(UC_ARM64_REG_X0) == 0
            assert u.reg_read(UC_ARM64_REG_SP) == g.STACK
        call(0x5e90)
        expected = (before & (0x3c | 0x1c0)) | (0x1000 if before & 0x800 else 0)
        assert writes == [{'address': hex(reg), 'bytes': 4, 'value': hex(expected)}], writes
        assert g.get32(u, reg) == expected
        connect_writes = list(writes)
        writes.clear()
        u.mem_write(PARAM + 0x10, struct.pack('<I', 1))
        g.put64(u, PARAM + 0x18, OUT)
        u.mem_write(OUT - 8, b'BEFORE!!' + b'\xa5' + b'!!AFTER!')
        call(0x62b0)
        assert not writes, writes
        assert bytes(u.mem_read(OUT - 8, 17)) == b'BEFORE!!' + bytes([level]) + b'!!AFTER!'
        assert g.get32(u, reg + 4) == (2 | level)
        assert g.get32(u, reg + 8) == 0xe2 and g.get32(u, reg + 12) == 0
        results.append({'physical_pin': pin, 'bank': pin // 64, 'local_pin': pin % 64,
                        'input_bit': level, 'output_latch_bit': 1, 'returned': level,
                        'connect_control_write': connect_writes, 'read_MMIO_writes': 0,
                        'output_canaries_unchanged': True})
r = {'phase': 'exact_ARM64_input_callback_emulation_passed', 'cases': results,
     'driver_sha256': hashlib.sha256(g.IMAGE.read_bytes()).hexdigest(),
     'limits': 'Models RAM registers, not read-only hardware bits or EGPIO ownership. Real input connections change pin configuration and require native validation.'}
p = W / 'input-emulation.json'
assert not p.exists()
p.write_text(json.dumps(r, indent=2) + '\n')
print(json.dumps(r, indent=2))
