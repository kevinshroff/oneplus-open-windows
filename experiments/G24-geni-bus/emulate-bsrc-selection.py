"""Validate the donor SPI driver's actual ARM64 UID selector against decoded data.

Executes original selector, bounded-copy helper and memmove instructions.
No function calls are mocked. Unicorn maps a local PE image, context and stack;
these are CPU/memory semantics, not Windows/PEP/hardware qualification.
Logical resource-buffer bounds are monitored independently of mapped pages.
"""
from pathlib import Path
import argparse, hashlib, importlib.util, json, struct
import pefile
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
from unicorn.arm64_const import *

W = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('aeob', W / 'decode-bsrc.py')
aeob = importlib.util.module_from_spec(spec)
spec.loader.exec_module(aeob)
BASE, ARENA, CONTEXT, STACK, DATA, END = (
    0x140000000, 0x30000000, 0x30001000, 0x3003ff00, 0x40000000, 0x180000000)
DRIVER_SHA = '34cabf2e7b59d3f8c0608da80dfdc705173c82427611312d32e7c1a9720e33ec'


def execute(raw, data, uid):
    pe = pefile.PE(data=raw)
    image = pe.get_memory_mapped_image()
    u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    u.mem_map(BASE, (len(image) + 0xfff) & ~0xfff)
    u.mem_write(BASE, image)
    u.mem_map(ARENA, 0x40000)
    u.mem_map(DATA, 0x20000)
    u.mem_write(DATA, data)
    u.mem_map(END, 0x1000)
    u.reg_write(UC_ARM64_REG_SP, STACK)
    u.reg_write(UC_ARM64_REG_CPACR_EL1, 3 << 20)
    u.reg_write(UC_ARM64_REG_X0, CONTEXT)
    u.reg_write(UC_ARM64_REG_X1, DATA)
    u.reg_write(UC_ARM64_REG_LR, END)
    u.mem_write(CONTEXT + 0x10, struct.pack('<I', uid))
    saved = [UC_ARM64_REG_X19,UC_ARM64_REG_X20,UC_ARM64_REG_X21,
             UC_ARM64_REG_X22,UC_ARM64_REG_X23,UC_ARM64_REG_X24,
             UC_ARM64_REG_X25,UC_ARM64_REG_X26,UC_ARM64_REG_X27,
             UC_ARM64_REG_X28,UC_ARM64_REG_X29]
    for i, reg in enumerate(saved):
        u.reg_write(reg, 0x80000000 + i * 0x100)
    before = [u.reg_read(reg) for reg in saved]
    violations = []

    def bounds_hook(uc, access, address, size, value, opaque):
        if DATA <= address < DATA + 0x20000 and address + size > DATA + len(data):
            violations.append({'pc': hex(uc.reg_read(UC_ARM64_REG_PC)),
                               'buffer_offset': address - DATA, 'bytes': size,
                               'access': access})
            uc.emu_stop()

    u.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, bounds_hook)
    u.emu_start(BASE + 0x1c9b8, END, count=1000000)
    if violations:
        return {'uid': uid, 'logical_buffer_violation': violations[0]}, None
    assert u.reg_read(UC_ARM64_REG_PC) == END, 'instruction budget exhausted'
    assert u.reg_read(UC_ARM64_REG_SP) == STACK
    assert [u.reg_read(reg) for reg in saved] == before
    status = u.reg_read(UC_ARM64_REG_W0)
    length, count = struct.unpack('<II', u.mem_read(DATA + 4, 8))
    assert 12 <= length <= len(data)
    return {'uid': uid, 'status': hex(status), 'output_bytes': length,
            'output_count': count, 'callee_saved_registers_and_stack_preserved': True}, \
        bytes(u.mem_read(DATA, length))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--driver', required=True, type=Path)
    parser.add_argument('--resources', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    assert not args.output.exists(), 'Preserve prior evidence'
    raw = args.driver.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == DRIVER_SHA
    report = {'driver_sha256': DRIVER_SHA,
              'executed_original_addresses': ['0x14001c9b8','0x14001dc90','0x14001e6c0'],
              'mocked_functions': [], 'files': [],
              'limitations': ['Local ARM64 CPU/memory emulation only; no Windows or PEP provider execution.',
                              'Logical out-of-buffer accesses are stopped before the mapped padding can be used.',
                              'No resource commands, hardware operations or native installation.']}
    for name, sha in aeob.HASHES.items():
        data = (args.resources / name).read_bytes()
        decoded = aeob.decode_container(data, sha)
        cases = []
        for uid, item in enumerate(decoded['arguments'], 1):
            case, out = execute(raw, data, uid)
            selected = aeob.encode_args([item])
            expected = b'AeoB' + struct.pack('<II', 12 + len(selected), 1) + selected
            assert case['status'] == '0x0' and out == expected, (name, case)
            case['exact_selected_record_and_rebuilt_header_match'] = True
            cases.append(case)
        invalid = []
        for uid in (0, 25, 26):
            case, out = execute(raw, data, uid)
            if uid == 25:
                assert 'logical_buffer_violation' in case, case
            else:
                assert case['status'] == '0xc0000023', case
            invalid.append(case)
        report['files'].append({'file': name, 'sha256': sha, 'valid_uid_cases': cases,
                                'invalid_uid_observations': invalid})
    report['valid_uid_cases_passed'] = sum(len(x['valid_uid_cases']) for x in report['files'])
    report['count_plus_one_uid_reads_past_logical_end'] = True
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'valid_uid_cases_passed': report['valid_uid_cases_passed'],
                      'count_plus_one_uid_reads_past_logical_end': True,
                      'no_native_installation': True}))


if __name__ == '__main__':
    main()
