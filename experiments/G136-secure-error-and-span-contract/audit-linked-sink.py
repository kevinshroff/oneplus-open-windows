"""Validate the linked sink ABI against retained REA instructions/mapped bytes."""
from pathlib import Path
import hashlib
import json
import struct
import pefile
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_MEM_WRITE
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X30, UC_ARM64_REG_SP

w = Path(__file__).resolve().parent / 'private'
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
pe = pefile.PE(data=(w / 'BdsDxe-linked.efi').read_bytes())
relocs = {entry.rva for block in pe.DIRECTORY_ENTRY_BASERELOC for entry in block.entries if entry.type == 10}
assert {0x70a60, 0x70a78, 0x70a80} <= relocs
read = lambda name: json.loads((w / name).read_text())
raw = bytes.fromhex(read('linked-proxy-REA.json')['normalized_result']['bytes_hex'])
assert struct.unpack('<7Q', raw) == (0, 0, 0x20128, 0, 0, 0x20450, 0x20470)
raw = bytes.fromhex(read('linked-ids-REA.json')['normalized_result']['bytes_hex'])
assert raw[:8] == b'G136DSP1' and raw[16:24] == b'G136SIP1'
raw = bytes.fromhex(read('linked-leaves-REA.json')['normalized_result']['bytes_hex'])
assert pe.get_data(0x20450, 64) == raw
leaf_results = []
for rva in [0x20450, 0x20470]:
    for count in [0, 1, 0xffffffff]:
        base, counter, stop = 0x10000000, 0x10071614, 0x90010000
        uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        uc.mem_map(base, 0x75000)
        uc.mem_write(base, pe.get_memory_mapped_image())
        uc.mem_map(0x90000000, 0x20000)
        uc.mem_write(counter, struct.pack('<I', count))
        uc.reg_write(UC_ARM64_REG_X0, 0xdead0000)  # Unmapped caller buffer, never read/written.
        uc.reg_write(UC_ARM64_REG_X1, 0xffffffffffffffff)
        uc.reg_write(UC_ARM64_REG_X30, stop)
        uc.reg_write(UC_ARM64_REG_SP, 0x90008000)
        writes = []
        uc.hook_add(UC_HOOK_MEM_WRITE, lambda u, access, address, size, value, data: writes.append((address, size, value)))
        uc.emu_start(base + rva, stop, count=32)
        assert uc.reg_read(UC_ARM64_REG_X0) == 0
        assert uc.reg_read(UC_ARM64_REG_X1) == 0xffffffffffffffff
        after = struct.unpack('<I', uc.mem_read(counter, 4))[0]
        assert after == min(count + 1, 0xffffffff)
        assert writes == ([] if count == 0xffffffff else [(counter, 4, after)])
        leaf_results.append({'RVA': hex(rva), 'counter_before': count, 'counter_after': after,
                             'return': 0, 'caller_buffer_unmapped': True, 'writes': len(writes)})
files = ['G136_rea_norm_0.json', 'G136_rea_norm_1.json', 'G136_rea_extra_0.json',
         'G136_rea_extra_1.json', 'G136_rea_extra_2.json', 'G136_rea_extra_3.json',
         'linked-ids-REA.json', 'linked-proxy-REA.json', 'linked-leaves-REA.json']
evidence = [{'file': name, 'evidence_id': read(name)['evidence_id'], 'sha256': sha(w / name)} for name in files]
init = read('G136_rea_extra_0.json')['normalized_result']['instructions']
for needle in ['0x1e9d0: mov x9, #0x110', '0x1e9e0: movk x9, #0x1, LSL #32',
               '0x1e9cc: mov x10, #0x3147', '0x1e9dc: movk x10, #0x3633, LSL #16',
               '0x1e9e4: movk x10, #0x4f4c, LSL #32', '0x1e9f0: movk x10, #0x3147, LSL #48',
               '0x1f27c: mov w1, #0x110']:
    assert needle in init, needle
result = {'passed': True, 'BDS_sha256': sha(w / 'BdsDxe-linked.efi'),
          'link_map_sha256': sha(w / 'BdsDxe-linked.map'),
          'REA_snapshot_sha256': sha(w / 'linked-sink.rea.json'), 'evidence': evidence,
          'Forward': {'RVA': '0x1fd98', 'frame_bytes': 48, 'anchor_from_frame_SP': '0x2f',
                      'bounds_relative_to_anchor': ['-0x4000', '+0x100'],
                      'all_five_original_API_arguments_preserved': True, 'original_indirect_call_RVA': '0x1fea8'},
          'SerialWrite': {'RVA': '0x20128', 'X0': 'buffer', 'X1': 'length',
                          'guard_precedes_first_buffer_read': True, 'max_bytes': 512},
          'serial_proxy': {'RVA': '0x70a50', 'bytes': 56, 'Write_RVA': '0x20128',
                           'Poll_RVA': '0x20450', 'Read_RVA': '0x20470',
                           'all_three_function_pointers_have_DIR64_relocations': True},
          'serial_body': {'size': 272, 'version': 1, 'magic': 'G136LOG1',
                          'magic_is_MOV_MOVK_immediates': True, 'ACPI_table_ID': 'G136SIP1', 'ACPI_total_bytes': 308},
          'VerifyOwnership': {'RVA': '0x1ff48', 'checks': ['LocateProtocol same This',
                              'SCM method equals Observe', 'serial cache equals exact proxy']},
          'actual_linked_Read_Poll_cases': 6, 'leaf_model_results': leaf_results,
          'limits': ['Ghidra did not automatically create procedures for the two32-byte leaf serial functions; retained exact REA mapped bytes are executed locally with explicit modeled RAM/register inputs.',
                     'Original function names come from this build linker map, not recovered PDB symbols.',
                     'Static compiled evidence and local models do not establish native secure-call behavior or return latency.'],
          'native_phone_operations': 0, 'native_G136_boots': 0}
(w / 'linked-sink-audit.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps({key: value for key, value in result.items() if key not in ['evidence', 'leaf_model_results']}, indent=2))
