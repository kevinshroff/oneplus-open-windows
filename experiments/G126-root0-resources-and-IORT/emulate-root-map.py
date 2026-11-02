"""Execute original kernel PCI-root creation/source-ID code against IORT bytes.

Allocation, the pre-existing SMMU catalogue, platform globals and already-sorted
qsort are modeled. Original root creation, filter, memory properties, map copy,
node validator, PCI root lookup and source-ID constructor execute in Unicorn.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import pefile
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_READ
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X30, UC_ARM64_REG_PC, UC_ARM64_REG_SP

p = argparse.ArgumentParser(description=__doc__)
for name in ['kernel', 'IORT', 'output']:
    p.add_argument('--'+name, type=Path, required=True)
bindings=p.add_mutually_exclusive_group(required=True)
bindings.add_argument('--evidence',type=Path)
bindings.add_argument('--bindings',type=Path,help='Compact REA byte identity receipt; no proprietary code bytes')
p.add_argument('--candidate',type=Path)
a = p.parse_args()
assert not a.output.exists()
raw = a.kernel.read_bytes()
assert hashlib.sha256(raw).hexdigest() == 'db0c8b367c1927eb4d39d922cb54da4621e9b3c241e2655d33c5ecd46719aa13'
table = a.IORT.read_bytes()
assert hashlib.sha256(table).hexdigest() == '7e0b0089aaf96fa3ec3f82d8cec30279814d9ad017d80714ffa22c5212081543'
pe = pefile.PE(data=raw)
def byte_records(value):
    if isinstance(value,dict):
        if 'bytes_hex' in value and 'address' in value: yield value
        for child in value.values(): yield from byte_records(child)
    elif isinstance(value,list):
        for child in value: yield from byte_records(child)
for name,rva,n in [('map-copy',0x4ac190,744),('sourceid',0x4a6868,308),('validator',0x4ad6b0,80),('lookup',0x4ac070,72),('root-creator-complete',0x4ac860,344),('root-filter-complete',0x4ad700,192),('memory-properties-complete',0x4abfe0,144)]:
    if a.evidence:
        found=list(byte_records(json.loads((a.evidence/(name+'-evidence.json')).read_text())))
        found=[x for x in found if int(x['address'],16)==pe.OPTIONAL_HEADER.ImageBase+rva]
        assert found and all(bytes.fromhex(x['bytes_hex'])==pe.get_data(rva,n)for x in found),name
    else:
        rows=json.loads(a.bindings.read_text())
        assert rows['kernel_sha256']==hashlib.sha256(raw).hexdigest()
        row=rows['routines'][name]
        assert row['RVA']==hex(rva) and row['read_bytes']==n and row['read_complete']
        assert row['bytes_sha256']==hashlib.sha256(pe.get_data(rva,n)).hexdigest(),name

BASE = pe.OPTIONAL_HEADER.ImageBase
DATA = 0x30000000
TABLE, ROOT, SMMU, DEVICE, OUT = [DATA+x for x in [0x1000, 0x3000, 0x4000, 0x6000, 0x7000]]
STACK, STOP = 0x70000000, 0x70010000
COPY, SOURCE, VALIDATE, FIND, SORT = [BASE+x for x in [0x4ac190, 0x4a6868, 0x4ad6b0, 0x4ac070, 0x457670]]
CREATE, FILTER, PROPERTIES = [BASE+x for x in [0x4ac860, 0x4ad700, 0x4abfe0]]
u32 = lambda b, at: struct.unpack_from('<I', b, at)[0]
u64 = lambda b, at: struct.unpack_from('<Q', b, at)[0]
ROOT_OFF = 0x490
assert table[ROOT_OFF] == 2 and u32(table, ROOT_OFF+8) == 6

def run(kind, platform, fault=None):
    firmware = bytearray(table)
    if kind=='candidate_artifact':
        assert a.candidate
        firmware=bytearray(a.candidate.read_bytes())
        assert hashlib.sha256(firmware).hexdigest()=='f84f40de8d0736cf7c55c25a5dd645c9529f9a7e3061b4a70d7a08dd11387f94'
    mapping = ROOT_OFF + u32(firmware, ROOT_OFF+12)
    if kind == 'strip_high':
        for i in range(6):
            struct.pack_into('<I', firmware, mapping+20*i, u32(firmware, mapping+20*i)&0xffff)
    elif kind == 'source_RID_SID_pair':
        struct.pack_into('<I', firmware, ROOT_OFF+8, 2)
        for i, (rid, sid) in enumerate([(0, 0x1400), (0x100, 0x1401)]):
            struct.pack_into('<5I', firmware, mapping+20*i, rid, 0, sid, 0x30, 0)
    elif kind not in ('native','candidate_artifact'):
        raise ValueError(kind)
    if fault=='revision':firmware[ROOT_OFF+3]=5
    elif fault=='short_header':struct.pack_into('<H',firmware,ROOT_OFF+1,31)
    elif fault=='single_flag_count':struct.pack_into('<I',firmware,mapping+4,1);struct.pack_into('<I',firmware,mapping+16,1)
    elif fault=='overlap':
        for i in range(2):struct.pack_into('<II',firmware,mapping+20*i,0,1)
    elif fault=='memory_properties':
        struct.pack_into('<I',firmware,ROOT_OFF+16,1);firmware[ROOT_OFF+23]=0
    elif fault not in (None,'duplicate_segment','allocation'):raise ValueError(fault)
    firmware[9] = 0
    firmware[9] = (-sum(firmware))&255
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    size = (pe.OPTIONAL_HEADER.SizeOfImage+4095)&~4095
    uc.mem_map(BASE, size)
    uc.mem_write(BASE, pe.get_memory_mapped_image())
    uc.mem_map(DATA, 0x10000)
    uc.mem_map(STACK, 0x20000)
    uc.mem_write(TABLE, bytes(firmware))
    put32 = lambda at, value: uc.mem_write(at, struct.pack('<I', value))
    put64 = lambda at, value: uc.mem_write(at, struct.pack('<Q', value))
    get32 = lambda at: struct.unpack('<I', uc.mem_read(at, 4))[0]
    get64 = lambda at: struct.unpack('<Q', uc.mem_read(at, 8))[0]
    smmu_head, root_head = BASE+0xc10740, BASE+0xc10730
    entry = SMMU+0xf0
    for at, value in [(smmu_head, entry), (smmu_head+8, entry), (entry, smmu_head), (entry+8, smmu_head), (entry+16, u64(firmware, 0x30+16)), (SMMU+0x108, SMMU+0x108), (SMMU+0x110, SMMU+0x108), (root_head, root_head), (root_head+8, root_head)]:
        put64(at, value)
    put64(BASE+0xdd36b0, 0)
    put32(BASE+0xc56528, platform)
    uc.mem_write(BASE+0xc56524, b'\0')
    if fault=='duplicate_segment':
        for at,value in [(root_head,ROOT),(root_head+8,ROOT),(ROOT,root_head),(ROOT+8,root_head)]:put64(at,value)
    selector_reads = []
    calls = {'sort_model': 0, 'validator_original': 0, 'root_lookup_original': 0, 'root_allocation_model':0,'source_allocation_model':0}
    visited = {x:set()for x in ['copy','source','validator','lookup','create','filter','properties']}
    allowed = [(COPY, COPY+744), (SOURCE, SOURCE+308), (VALIDATE, VALIDATE+76), (FIND, FIND+52), (CREATE,CREATE+344), (FILTER,FILTER+180), (PROPERTIES,PROPERTIES+132)]
    phase='create'

    def code(cpu, address, size, user):
        if address == BASE+0x49c8a0:
            if phase=='create':
                assert cpu.reg_read(UC_ARM64_REG_X0)==0
                assert cpu.reg_read(UC_ARM64_REG_X1)==(u32(firmware,ROOT_OFF+8)+1)*48
                ptr=ROOT;calls['root_allocation_model']+=1
                assert calls['root_allocation_model']==1
                if fault=='allocation':
                    cpu.reg_write(UC_ARM64_REG_X0,0xc000009a)
                    cpu.reg_write(UC_ARM64_REG_PC,cpu.reg_read(UC_ARM64_REG_X30))
                    return
                uc.mem_write(ptr,bytes(cpu.reg_read(UC_ARM64_REG_X1)))
            else:
                assert cpu.reg_read(UC_ARM64_REG_X0)==get32(ROOT+0x24) and cpu.reg_read(UC_ARM64_REG_X1)==0x20
                ptr=DATA+0x8000+calls['source_allocation_model']*256
                assert ptr+256<DATA+0x10000
                calls['source_allocation_model']+=1
            put64(cpu.reg_read(UC_ARM64_REG_X2),ptr)
            cpu.reg_write(UC_ARM64_REG_X0,0)
            cpu.reg_write(UC_ARM64_REG_PC,cpu.reg_read(UC_ARM64_REG_X30))
            return
        if address == SORT:
            assert cpu.reg_read(UC_ARM64_REG_X0) == ROOT+0x30
            count = cpu.reg_read(UC_ARM64_REG_X1)
            assert count == get32(ROOT+0x24) and cpu.reg_read(UC_ARM64_REG_X2) == 0x30
            values = [get32(ROOT+0x50+48*i) for i in range(count)]
            assert values == sorted(values), 'sort model covers only already-sorted test inputs'
            calls['sort_model'] += 1
            cpu.reg_write(UC_ARM64_REG_PC, cpu.reg_read(UC_ARM64_REG_X30))
            return
        if address == VALIDATE:
            calls['validator_original'] += 1
        if address == FIND:
            calls['root_lookup_original'] += 1
        for key,(lo,hi)in zip(visited,allowed):
            if lo<=address<hi: visited[key].add(address)
        if not any(lo <= address < hi for lo, hi in allowed):
            raise AssertionError('Unmodeled code address '+hex(address))

    def memory(cpu, access, address, size, value, user):
        if DEVICE <= address < DEVICE+32:
            selector_reads.append({'offset': address-DEVICE, 'bytes': size})

    uc.hook_add(UC_HOOK_CODE, code)
    uc.hook_add(UC_HOOK_MEM_READ, memory)

    def call(address, args):
        for reg, value in zip([UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3, UC_ARM64_REG_X4], args+[0]*(5-len(args))):
            uc.reg_write(reg, value)
        uc.reg_write(UC_ARM64_REG_X30, STOP)
        uc.reg_write(UC_ARM64_REG_SP, STACK+0xf000)
        uc.emu_start(address, STOP, count=200000)
        assert uc.reg_read(UC_ARM64_REG_PC) == STOP, 'instruction limit, no completion claim'
        return uc.reg_read(UC_ARM64_REG_X0)&0xffffffff

    create_status=call(CREATE,[TABLE,TABLE+ROOT_OFF])
    if fault:
        expected={'revision':0x110,'short_header':0x108,'single_flag_count':0x110,'overlap':0x208,'memory_properties':0x108,'duplicate_segment':0x208,'allocation':0}
        assert get64(BASE+0xdd36b0)==expected[fault],(fault,hex(get64(BASE+0xdd36b0)))
        assert create_status==(0xc000009a if fault=='allocation'else 0)
        assert get64(root_head)==(ROOT if fault=='duplicate_segment'else root_head)
        assert calls['sort_model']==0
        assert bytes(uc.mem_read(TABLE,len(firmware)))==bytes(firmware)
        return {'case':kind,'fault':fault,'modeled_platform_global':platform,'return_status':hex(create_status),'diagnostic_flags':hex(get64(BASE+0xdd36b0)),'new_root_created':False,'no_map_copy':not visited['copy'],'calls':calls,'firmware_input_unchanged':True}
    assert create_status==0
    assert get64(BASE+0xdd36b0) == 0, hex(get64(BASE+0xdd36b0))
    assert get64(root_head)==ROOT and get64(root_head+8)==ROOT
    assert get32(ROOT+0x10)==1 and get32(ROOT+0x20)==0x31
    assert bytes(uc.mem_read(ROOT+0x18,2))==firmware[ROOT_OFF+0x1c:ROOT_OFF+0x1e]
    phase='source'
    count = get32(ROOT+0x24)
    assert count == u32(firmware, ROOT_OFF+8)
    mappings = [{'input_base': get32(ROOT+0x50+48*i), 'output_base': get32(ROOT+0x54+48*i), 'count': get32(ROOT+0x58+48*i)} for i in range(count)]
    expected = [{'input_base': u32(firmware,mapping+20*i), 'output_base': u32(firmware,mapping+20*i+8), 'count': u32(firmware,mapping+20*i+4)+1} for i in range(count)]
    assert mappings == expected
    assert get32(SMMU+0x24)&1
    results = []
    for rid in [0, 1, 2, 13, 16, 80, 143, 0x100, 0xffff]:
        uc.mem_write(DEVICE, bytes(32))
        uc.mem_write(DEVICE+12, struct.pack('<H', rid))
        rc = call(SOURCE, [SMMU, DEVICE, OUT, 0, 1])
        match = any(x['input_base'] <= rid < x['input_base']+x['count'] for x in mappings)
        assert (rc == 0) == match, (kind, rid, hex(rc), match)
        put64(OUT,0)
        constructed=call(SOURCE,[SMMU,DEVICE,OUT,0,0])
        assert constructed==rc
        sid=None
        if match:
            ptr=get64(OUT);assert ptr and get32(ptr+16)==1
            sid=get32(ptr+20);assert get32(ptr+24)==1
            expected_sid=next(x['output_base']+rid-x['input_base']for x in mappings if x['input_base']<=rid<x['input_base']+x['count'])
            assert sid==expected_sid
        else:assert get64(OUT)==0
        results.append({'selector':hex(rid),'status':hex(rc),'accepted':rc==0,'constructed_stream_id':None if sid is None else hex(sid)})
    assert bytes(uc.mem_read(TABLE,len(firmware))) == bytes(firmware)
    assert any(x == {'offset':12,'bytes':2} for x in selector_reads)
    return {'case': kind, 'modeled_platform_global':platform,'root_created_by_original_code':True,'root_memory_properties':list(uc.mem_read(ROOT+0x28,3)), 'mappings': mappings, 'queries': results, 'calls': calls, '16_bit_selector_load_observed': True, 'firmware_input_unchanged':True,'original_code_coverage':{k:{'instructions':len(v),'first':hex(min(v)),'last':hex(max(v))}for k,v in visited.items()}}

cases=[]
for platform in [0,2,3,11]:
    group=[run(kind,platform)for kind in ['native','strip_high','source_RID_SID_pair']]
    if a.candidate:
        group.append(run('candidate_artifact',platform))
        assert group[-1]['queries']==group[2]['queries']
    assert not any(x['accepted'] for x in group[0]['queries'])
    assert not next(x for x in group[1]['queries'] if x['selector']=='0x100')['accepted']
    assert next(x for x in group[2]['queries'] if x['selector']=='0x100')['accepted']
    cases+=group
negative=[run('native',0,fault)for fault in ['revision','short_header','single_flag_count','overlap','memory_properties','duplicate_segment','allocation']]
result = {'passed':True,'original_kernel_sha256':hashlib.sha256(raw).hexdigest(),'native_IORT_sha256':hashlib.sha256(table).hexdigest(),'cases':cases,'root_creation_failure_cases':negative,'native_operations':0,'REA_read_bytes_bound':True,'scope':'Seven original routines execute, including complete root creation/filter/memory-property path. SMMU catalogue, zeroed heap allocation, global state and platform values0/2/3/11 are modeled; qsort covers only already-sorted test inputs. Validation-only and source construction both execute. Seven injected root failure cases verify flags/catalogue; success status alone does not establish a created root. Not full IORT processing, loaded-kernel catalogue, hardware RID, DMA or candidate-firmware acceptance.'}
a.output.write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
