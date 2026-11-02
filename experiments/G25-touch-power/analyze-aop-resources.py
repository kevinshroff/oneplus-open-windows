"""Decode captured AOP properties and cross-check original Thumb query code.

All emulation is local memory/CPU evidence. No device or mocked function calls.
AOP local-memory aliases are the same derived view documented separately.
"""
import argparse, hashlib, json, struct, zlib
from pathlib import Path
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_MODE_MCLASS
from unicorn.arm_const import *

AOP_SHA='e212e15ae63f5352ad3a7bd09429746177cdedd7582f242a56891def9af849e6'
CFG_SHA='47c7b6a37df8c6da48c4de36baa7540548f34935c550559661e43d220789c140'
ROOT=0x81c80000
ARENA, HANDLE, NAME, STACK, END = 0x30000000,0x30001000,0x30002000,0x3003f000,0x10000000

class Elf:
    def __init__(self, path, expected):
        self.path=path; self.raw=path.read_bytes()
        self.sha=hashlib.sha256(self.raw).hexdigest(); assert self.sha==expected
        b=self.raw
        assert b[:7]==b'\x7fELF\x01\x01\x01' and struct.unpack_from('<H',b,18)[0]==40
        phoff=struct.unpack_from('<I',b,28)[0]; size,count=struct.unpack_from('<HH',b,42)
        assert size==32 and 0<count<=32 and phoff+size*count<=len(b)
        self.segments=[]
        for i in range(count):
            typ,off,va,pa,fs,ms,flags,align=struct.unpack_from('<8I',b,phoff+i*size)
            if typ==1:
                assert off+fs<=len(b) and fs<=ms
                self.segments.append(dict(offset=off,va=va,pa=pa,filesz=fs,memsz=ms))
    def read(self, address, size):
        matches=[s for s in self.segments if s['va']<=address and address+size<=s['va']+s['filesz']]
        assert size>0 and len(matches)==1,(hex(address),size)
        s=matches[0]; off=s['offset']+address-s['va']
        return self.raw[off:off+size]
    def words(self, address, count):
        assert 0<count<=512
        return list(struct.unpack('<'+'I'*count,self.read(address,4*count)))
    def string(self,address):
        if not address:return None
        s=next(s for s in self.segments if s['va']<=address<s['va']+s['filesz'])
        raw=self.read(address,min(128,s['filesz']-(address-s['va'])))
        assert b'\0' in raw
        return raw.split(b'\0')[0].decode('ascii')


def emulate_query(aop,cfg,group,key):
    u=Uc(UC_ARCH_ARM,UC_MODE_THUMB|UC_MODE_MCLASS)
    segments=[]; pages=set()
    for elf in (aop,cfg):
        for s in elf.segments:
            va=s['va']
            if elf is aop and va in [0xb000000,0xb0e0000]:va-=0xb000000
            segments.append((elf,s,va))
            pages.update(range(va&~0xfff,(va+s['memsz']+0xfff)&~0xfff,0x1000))
    for p in sorted(pages):u.mem_map(p,0x1000)
    for elf,s,va in segments:u.mem_write(va,elf.raw[s['offset']:s['offset']+s['filesz']])
    u.mem_map(ARENA,0x40000);u.mem_map(END,0x1000)
    u.mem_write(0xe6f40,struct.pack('<I',ROOT))
    u.mem_write(HANDLE,struct.pack('<I',zlib.crc32(group.encode())))
    u.mem_write(NAME,key.encode()+b'\0')
    regs=[UC_ARM_REG_R4,UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_R7,UC_ARM_REG_R8,UC_ARM_REG_R9,UC_ARM_REG_R10,UC_ARM_REG_R11]
    for i,r in enumerate(regs):u.reg_write(r,0x80001000+i*0x100)
    saved=[u.reg_read(r)for r in regs]
    u.reg_write(UC_ARM_REG_SP,STACK);u.reg_write(UC_ARM_REG_LR,END|1)
    u.reg_write(UC_ARM_REG_R0,HANDLE);u.reg_write(UC_ARM_REG_R1,NAME)
    try:
        u.emu_start(0xc19d,END,count=2000000)
    except Exception as e:
        raise RuntimeError(dict(key=key,pc=hex(u.reg_read(UC_ARM_REG_PC)),sp=hex(u.reg_read(UC_ARM_REG_SP)),cpsr=hex(u.reg_read(UC_ARM_REG_CPSR)),error=str(e))) from e
    assert u.reg_read(UC_ARM_REG_PC)==END
    assert u.reg_read(UC_ARM_REG_SP)==STACK
    assert [u.reg_read(r)for r in regs]==saved
    return u.reg_read(UC_ARM_REG_R0)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--aop',required=True,type=Path);p.add_argument('--config',required=True,type=Path)
    p.add_argument('--output',required=True,type=Path);a=p.parse_args()
    assert not a.output.exists()
    aop=Elf(a.aop,AOP_SHA);cfg=Elf(a.config,CFG_SHA)
    table,count,magic,version=cfg.words(ROOT,4)
    assert count==4 and magic==0xa0da7a and version==7
    groups=[cfg.words(table+12*i,3)for i in range(count)]
    pmic=next(g for g in groups if g[0]==zlib.crc32(b'pmic'))
    assert pmic[1]==24
    props={}
    for i in range(pmic[1]):
        h,v=cfg.words(pmic[2]+8*i,2);assert h not in props;props[h]=v
    # All 24 original property-name strings observed in the AOP image.
    names=['PERIPH_BITMAP','RPMH_DRV_ID','KAILUA_WA','SMPS_RAIL','BOB_RAIL',
           'SMPS_DEP','BOB_DEP','LDO_DEP','LDO_NUM','SMPS_NUM','BOB_NUM','PSTM_SEQ',
           'TARGET_RSRC_INFO','TARGET_RSRC_NUM','PSTM_INFO','CLK_RSRC','CLK_DEP',
           'CLK_INFO','MAX_VOL_WA','SMPS_RSRC','LDO_RSRC','LDO_RAIL','BOB_RSRC',
           'MIN_SETTLING_TIME_THR']
    decoded={};cases=[]
    for short in names:
        key='PM_PROP_'+short;h=zlib.crc32(key.encode());assert h in props
        expected=props[h];actual=emulate_query(aop,cfg,'pmic',key);assert actual==expected
        decoded[key]=dict(crc32=hex(h),value=hex(actual))
        cases.append(dict(key=key,value=hex(actual),original_code_matches_decoder=True))
    assert len(decoded)==len(props)
    for group,key in [('pmic','MISSING_PROPERTY'),('missing_group','PM_PROP_LDO_RSRC')]:
        actual=emulate_query(aop,cfg,group,key);assert actual==0
        cases.append(dict(group=group,key=key,value='0x0',expected_missing=True))
    def prop(n):return int(decoded['PM_PROP_'+n]['value'],16)
    counts=cfg.words(prop('LDO_NUM'),14)
    resources=cfg.words(prop('LDO_RSRC'),14);rails=cfg.words(prop('LDO_RAIL'),14)
    mapping=[]
    for idx,n in enumerate(counts):
        if not n:continue
        assert n<=32 and resources[idx] and rails[idx]
        for ordinal in range(1,n+1):
            name,alias=cfg.words(resources[idx]+ordinal*8,2)
            if not name:continue
            raw=cfg.read(rails[idx]+(ordinal-1)*36,36)
            mapping.append(dict(pmic_index=idx,ldo_number=ordinal,
                                resource=cfg.string(name),alias=cfg.string(alias),
                                resource_pair_address=hex(resources[idx]+ordinal*8),
                                rail_config_address=hex(rails[idx]+(ordinal-1)*36),
                                rail_config_hex=raw.hex(),
                                configured_min_millivolts=struct.unpack_from('<H',raw,4)[0],
                                configured_max_millivolts=struct.unpack_from('<H',raw,6)[0]))
    bitmaps=[]
    bitmap_address=prop('PERIPH_BITMAP')
    for idx in range(14):
        raw=cfg.read(bitmap_address+idx*32,32)
        present=[i for i in range(256) if raw[i//8] & (1<<(i%8))]
        bitmaps.append(dict(pmic_index=idx,address=hex(bitmap_address+idx*32),implemented_peripherals=[hex(i)for i in present]))
    assert all(hex(i) in bitmaps[1]['implemented_peripherals'] for i in range(0xc1,0xd2))
    touch=next(x for x in mapping if x['resource']=='ldob4')
    assert touch['pmic_index']==1 and touch['ldo_number']==4
    assert touch['configured_min_millivolts']==touch['configured_max_millivolts']==1800
    report=dict(aop_sha256=AOP_SHA,config_sha256=CFG_SHA,property_group='pmic',
                properties=decoded,original_thumb_query='0xc19c',crc32_function='0xc16c',
                query_code_bytes_unchanged=True,mocked_functions=[],
                emulation_cases=cases,ldo_resources=mapping,peripheral_bitmaps=bitmaps,touch_supply=touch,
                limitations=['Local decoding and original CPU/memory emulation only.',
                             'Global property-table pointer initialized to captured config root; not evidence of live AOP selection.',
                             'PMIC index is not converted to a physical SID without separate identity evidence.',
                             'The live AOP load-address probe caused a synchronous abort; do not repeat it.',
                             'No regulator, PMIC, GPIO, clock or firmware writes were performed by this analysis.'])
    a.output.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(dict(original_queries_passed=len(cases),ldo_resources=len(mapping),touch_supply=touch)))

if __name__=='__main__':main()
