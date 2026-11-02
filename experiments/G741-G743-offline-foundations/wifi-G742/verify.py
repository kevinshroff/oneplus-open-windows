#!/usr/bin/env python3
"""Offline arithmetic audit of the 22D260 allocation path at held event46.

Never reads memory, emits debugger commands, qualifies a mapping, or resumes.
Capture receipts and RAM inventory are supplied by root, not authenticated here.
"""
import argparse
import json
import struct
from pathlib import Path

U64 = (1 << 64) - 1
MAX_OBJECTS = 4096  # audit resource limit, not a driver invariant


class Invalid(ValueError):
    pass


def need(ok, why):
    if not ok:
        raise Invalid(why)


def uint(v, name, bits=64):
    need(type(v) is int and 0 <= v < 1 << bits, 'invalid integer: ' + name)
    return v


def span(a, n, label):
    uint(a, label); uint(n, label)
    need(a > 0 and n > 0 and a + n <= 1 << 64, 'empty/wrapped range: ' + label)
    return a, a + n


def receipt(r, address, size, label):
    need(type(r) is dict, 'missing read receipt: ' + label)
    need(r.get('address') == address and r.get('requested') == size and
         r.get('actual_bytes') == size and type(r.get('hresult')) is int and
         r['hresult'] == 0, 'inexact/failed read: ' + label)
    try:
        b = bytes.fromhex(r['raw_hex'])
    except (KeyError, TypeError, ValueError) as e:
        raise Invalid('invalid bytes: ' + label) from e
    need(len(b) == size, 'wrong byte length: ' + label)
    return b


def audit(c):
    need(c.get('schema') == 'g742-root-supplied-capture/1', 'wrong capture schema')
    base = uint(c['driver_base'], 'driver_base')
    pool = uint(c['pool'], 'pool')
    for label, a, n in [('driver', base, 0x3968c0), ('pool', pool, 0x7eb8)]:
        span(a, n, label)
        need(a >= 0xffff000000000000 and a + n <= 1 << 64 and a % 8 == 0,
             'non-kernel/unaligned ' + label)
    need(c['event_id'] == 46 and c['pc'] == base + 0x22e250,
         'requires actual event46 entry')
    need(c['execution_status'] == 6, 'requires held6')
    b = receipt(c['pool_98_F7'], pool + 0x98, 0x60, 'pool98..F7')
    q = lambda off: struct.unpack_from('<Q', b, off - 0x98)[0]
    w = lambda off: struct.unpack_from('<I', b, off - 0x98)[0]
    total, chunk_size, payload = q(0x98), q(0xa0), q(0xb0)
    chunks_va, vector_va = q(0xb8), q(0xc0)
    count, maxcount, allocated, alignment = w(0xc8), w(0xcc), w(0xd0), w(0xe0)
    transfer, length = q(0xe8), q(0xf0)
    state = struct.unpack('<I', receipt(c['state'], pool + 0x5e0, 4, 'state'))[0]
    need(state & 0x1f6e, 'state bypasses programming at current observation')
    need(0 < chunk_size <= 0xffffffff and 0 < payload <= 0xffffffff,
         'unsupported/empty chunk size or payload')
    need(0 < alignment <= 0xffffffff and alignment & (alignment-1) == 0,
         'alignment must be nonzero power of two')
    # 22D260 performs 64-bit ceil arithmetic, then stores counts in DWORDs.
    expected_count = (payload + chunk_size - 1) // chunk_size
    expected_max = (0x780000 + chunk_size - 1) // chunk_size
    expected_alloc = (max(payload, 0x780000) + chunk_size - 1) // chunk_size + 1
    need((count, maxcount, allocated) == (expected_count, expected_max, expected_alloc),
         'not consistent with 22D260 default allocation path; cached/other path unresolved')
    need(1 <= count < allocated <= MAX_OBJECTS, 'object count exceeds bounded audit policy')
    for label, a, n in [('chunks', chunks_va, allocated*0x30), ('vector', vector_va, count*16)]:
        span(a, n, label)
        need(a >= 0xffff000000000000 and a % 8 == 0, 'non-kernel/unaligned ' + label)
    raw = receipt(c['chunks'], chunks_va, allocated*0x30, 'chunk array')
    vector = receipt(c['vector'], vector_va, count*16, 'CPU descriptor vector')
    chunks = [struct.unpack_from('<6Q', raw, i*0x30) for i in range(allocated)]
    ranges = []
    for i, (cpu, aligned_cpu, capacity, useful, dma, raw_dma) in enumerate(chunks):
        expected_useful = chunk_size if i < allocated-1 else (allocated-1)*16
        need(useful == expected_useful and capacity == useful + alignment - 1,
             f'chunk{i}: allocation capacity mismatch')
        need(capacity <= 0xffffffff, f'chunk{i}: allocator DWORD truncation')
        span(cpu, capacity, f'chunk{i} CPU'); span(raw_dma, capacity, f'chunk{i} DMA')
        need(cpu >= 0xffff000000000000, f'chunk{i}: CPU pointer not kernel')
        expected_dma = (raw_dma + alignment - 1) & ~(alignment - 1)
        need(expected_dma <= U64 and dma == expected_dma and aligned_cpu == cpu + dma - raw_dma,
             f'chunk{i}: aligned CPU/DMA relationship mismatch')
        need(dma + useful <= raw_dma + capacity, f'chunk{i}: useful DMA range outside allocation')
        span(dma, useful, f'chunk{i} useful DMA')
        ranges.append({'kind':'allocation_metadata', 'index':i, 'start':raw_dma,
                       'end_exclusive':raw_dma+capacity})
    need(vector_va == chunks[-1][1], 'C0 differs from final aligned descriptor allocation')
    remaining = payload
    for i in range(count):
        dma, n = struct.unpack_from('<2Q', vector, i*16)
        expected_n = min(remaining, chunk_size)
        need((dma, n) == (chunks[i][4], expected_n), f'descriptor{i}: address/length mismatch')
        span(dma, n, f'descriptor{i}')
        remaining -= n
        ranges.append({'kind':'payload_descriptor', 'index':i, 'start':dma, 'end_exclusive':dma+n})
    need(remaining == 0, 'descriptor payload remainder')
    need(transfer == chunks[0][4] and length == total, 'E8/F0 differ from preparation stores')
    need(0 < length <= 0xffffffff, 'F0 is empty or exceeds DWORD BHI write width')
    span(transfer, length, 'BHI transfer')
    need(length <= chunks[0][3], 'BHI contiguous transfer exceeds first chunk capacity')
    ranges.append({'kind':'BHI_contiguous_transfer', 'start':transfer, 'end_exclusive':transfer+length})
    # Numeric RAM containment is diagnostic only; it never certifies ownership.
    ram = c.get('physical_ram_inventory', [])
    for r in ram:
        span(uint(r['start'], 'RAM start'), uint(r['length'], 'RAM length'), 'RAM')
    for r in ranges:
        r['within_supplied_ram_inventory'] = any(v['start'] <= r['start'] and
            r['end_exclusive'] <= v['start'] + v['length'] for v in ram) if ram else None
    return {'schema':'g742-offline-arithmetic-audit/1', 'arithmetic_result':'consistent',
            'observed_state':state, 'state_selects_programming_now':True,
            'context_verified':False, 'DMA_readiness':False, 'resume_authorized':False,
            'path_scope':'22D260 default allocation path only', 'ranges':ranges,
            'limits':['Root must bind all receipts to the same held event, boot, image and pool.',
                      'Numeric allocation metadata and RAM containment prove no ownership, mapping, coherency or lifetime.',
                      'M=0 identity recipe creates no page-table RAM coverage; post-EBS equality proves registers only.',
                      'Entry state may change during calls before the later state test; no execution or completion proved.']}


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('capture', type=Path); p.add_argument('--out', type=Path, required=True)
    a = p.parse_args()
    try:
        result = audit(json.loads(a.capture.read_text()))
    except (Invalid, KeyError, TypeError, ValueError, struct.error) as error:
        result = {'arithmetic_result':'refused', 'reason':str(error), 'DMA_readiness':False,
                  'resume_authorized':False}
    a.out.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result['arithmetic_result']=='consistent' else 1)
