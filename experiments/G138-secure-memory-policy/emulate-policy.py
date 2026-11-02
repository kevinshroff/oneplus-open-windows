"""Exercise captured TZ instructions in an isolated ARM64 model.

Secure global values are initialized from the captured devcfg properties.
Metadata span is supplied by an explicit ELF reconstruction; persistent-ledger
hashing and logging are stubs. PAC/BTI/RETAA mechanics are modeled. No native
SMC, MMIO, DSP instruction, secure ownership transfer or target write occurs.
"""
from pathlib import Path
import argparse
import hashlib
import json
import struct
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn.arm64_const import *

w=Path(__file__).resolve().parent
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--tz',type=Path,default=w/'private/tz_a.img')
parser.add_argument('--dtb',type=Path,default=w.parent/'charging-G107/private/native-adsp_dtb.mdt')
parser.add_argument('--proof-dir',type=Path,default=w/'private')
parser.add_argument('--policy',type=Path,default=w/'private/devcfg-policy.json')
parser.add_argument('--output',type=Path,default=w/'private/policy-model.json')
args=parser.parse_args()
raw=args.tz.read_bytes()
assert hashlib.sha256(raw).hexdigest()=='dbd1e8e09fd6aca142755989b3ce97b5a271dec3432a572a01167849be83ae80'
h=struct.unpack_from('<16sHHIQQQIHHHHHH',raw)
loads=[]
for i in range(h[10]):
    typ,flags,off,va,pa,n,mem,align=struct.unpack_from('<IIQQQQQQ',raw,h[5]+i*h[9])
    if typ==1 and mem:loads.append((va,off,n,mem))
def filebytes(address,n):
    rows=[(va,off,size) for va,off,size,mem in loads if va<=address<=address+n<=va+size]
    assert len(rows)==1
    va,off,size=rows[0];return raw[off+address-va:off+address-va+n]
for name in ['validation','state_overlap','region']:
    proof=json.loads((args.proof_dir/('REA-'+name+'.json')).read_text())
    d=proof['normalized_result'];address=int(d['address'],16)
    assert d['complete'] and bytes.fromhex(d['bytes_hex'])==filebytes(address,d['returned_bytes'])

mdt=args.dtb.read_bytes()
assert hashlib.sha256(mdt).hexdigest()=='5476d25e617ebf2c51128fe1405d01f8731547ce14778a62893625dda7d0e0b1'
assert mdt[:6]==b'\x7fELF\x01\x01'
entry=struct.unpack_from('<I',mdt,24)[0]
phoff=struct.unpack_from('<I',mdt,28)[0];count=struct.unpack_from('<H',mdt,44)[0]
selected=[]
for i in range(count):
    typ,off,va,pa,filesz,memsz,flags,align=struct.unpack_from('<8I',mdt,phoff+i*32)
    if typ==1 and not(flags&(1<<20)) and flags&0x7000000!=0x2000000 and ((flags>>21)&7) not in (3,4):
        selected.append((pa,memsz))
lo=min(p for p,n in selected)&~4095
hi=(max(p+n for p,n in selected)+4095)&~4095
assert (entry,lo,hi)==(0x9e980000,0x9e980000,0x9e983000)
policies=json.loads(args.policy.read_text())
assert len(policies)==2 and all((p['start'],p['end_exclusive'])==(0x8a800000,0xa3280000) for p in policies)
START,END=policies[0]['start'],policies[0]['end_exclusive']
ARENA,STOP=0x30000000,0x20000000
CTX,LEDGER,OTHER=ARENA+0x1000,ARENA+0x10000,ARENA+0x20000
RANGES=[(0xd835bc28,0xd835bd2c),(0xd835d824,0xd835d8d0),
        (0xd835ba8c,0xd835ba98),(0xd83681b0,0xd8368318),
        (0xd835b7f0,0xd835b968)]

def run(name,base,size,*,function='chain',state=1,full=False,overlap=False,
        digest_error=0,metadata_entry=entry):
    u=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
    pages=set()
    for va,off,n,mem in loads:pages.update(range(va&~4095,(va+mem+4095)&~4095,4096))
    for page in sorted(pages):u.mem_map(page,4096)
    for va,off,n,mem in loads:
        if n:u.mem_write(va,raw[off:off+n])
    u.mem_map(ARENA,0x100000);u.mem_map(STOP,4096)
    def put(address,fmt,*values):u.mem_write(address,struct.pack('<'+fmt,*values))
    def ret(value=0):
        u.reg_write(UC_ARM64_REG_X0,value&((1<<64)-1))
        u.reg_write(UC_ARM64_REG_PC,u.reg_read(UC_ARM64_REG_LR))
    u.mem_write(CTX,filebytes(0xd8485208,0x498))
    assert struct.unpack('<I',u.mem_read(CTX+0x440,4))[0]==36
    assert bytes(u.mem_read(CTX+0x45c,4))==bytes(4)
    put(CTX+0x490,'I',state);put(CTX+0x78,'Q',metadata_entry)
    put(0xd84a1808,'QQ',START,END);put(0xd84a1818,'Q',LEDGER)
    put(LEDGER+0x20,'I',32 if full else 0)
    put(0xd84a0a60+36*8,'Q',CTX)
    if overlap:
        put(0xd84a0a60+1*8,'Q',OTHER)
        put(OTHER+0x490,'I',3);put(OTHER+0xc0,'QQ',base+4096,base+8192)
    events=[];writes=[]
    def write_hook(uc,kind,address,n,value,unused):
        assert ARENA<=address<=address+n<=ARENA+0x100000,hex(address)
        if address<ARENA+0x30000:writes.append({'address':address,'bytes':n})
    def hook(uc,pc,n,unused):
        if pc==0xd833be88:
            events.append({'stub':'secure_log','code':uc.reg_read(UC_ARM64_REG_X2)&0xffffffff});ret();return
        if pc==0xd83683f8:
            events.append({'stub':'persistent_ledger_hash','result':digest_error});ret(digest_error);return
        if pc==0xd835b478:
            assert uc.reg_read(UC_ARM64_REG_X0)==CTX
            put(uc.reg_read(UC_ARM64_REG_X1),'Q',lo);put(uc.reg_read(UC_ARM64_REG_X2),'Q',hi)
            events.append({'stub':'metadata_span','min':lo,'end':hi});ret();return
        assert any(a<=pc<b for a,b in RANGES),'Unexpected instruction '+hex(pc)
        word=struct.unpack('<I',uc.mem_read(pc,4))[0]
        if word in (0xdac103fe,0xd503245f,0xd503249f):
            uc.reg_write(UC_ARM64_REG_PC,pc+4) # PAC/BTI modeled, unchanged original file.
        elif word==0xd65f0bff:ret(uc.reg_read(UC_ARM64_REG_X0)) # RETAA modeled as authenticated return.
    u.hook_add(UC_HOOK_CODE,hook);u.hook_add(UC_HOOK_MEM_WRITE,write_hook)
    stack=ARENA+0xfffe0
    u.reg_write(UC_ARM64_REG_SP,stack);u.reg_write(UC_ARM64_REG_LR,STOP)
    for reg,value in [(UC_ARM64_REG_X0,CTX),(UC_ARM64_REG_X1,base),(UC_ARM64_REG_X2,base+size)]:u.reg_write(reg,value)
    target={'chain':0xd835bc28,'gate':0xd835d824,'span':0xd835b7f0}[function]
    u.emu_start(target,STOP,count=10000)
    assert u.reg_read(UC_ARM64_REG_PC)==STOP and u.reg_read(UC_ARM64_REG_SP)==stack
    return {'case':name,'function':function,'base':base,'bytes':size,
            'result':u.reg_read(UC_ARM64_REG_X0),'events':events,
            'context_state_after':struct.unpack('<I',u.mem_read(CTX+0x490,4))[0],
            'ledger_count_after':struct.unpack('<I',u.mem_read(LEDGER+0x20,4))[0],
            'model_data_write_count':len(writes)}

plans=[
('G134 relocated DTB',0xa9f80000,0x80000,{},0x30003e),
('shortening same relocated DTB',0xa9f80000,0x3000,{},0x30003e),
('original DTB reservation',0x9e980000,0x80000,{},0),
('original DTB minimum span',0x9e980000,0x3000,{},0),
('below permitted start',START-4096,0x3000,{},0x30003e),
('last valid three pages',END-0x3000,0x3000,{},0),
('one page over end',END-0x2000,0x3000,{},0x30003e),
('wrong context state',0x9e980000,0x3000,{'state':0},0x300015),
('full persistent ledger',0x9e980000,0x3000,{'full':True},0x30003e),
('ledger persistence error',0x9e980000,0x3000,{'digest_error':9},0x30003e),
('existing active overlap',0x9e980000,0x80000,{'overlap':True},0x300016),
('undersized metadata span',0x9e980000,0x2000,{},0x300005),
('unaligned larger span',0x9e980000,0x3001,{},0x300006),
('wrong metadata entry',0x9e980000,0x80000,{'metadata_entry':lo-1},0x300007),
('isolated 512 KiB span check',0xa9f80000,0x80000,{'function':'span'},0),
('isolated 12 KiB span check',0xa9f80000,0x3000,{'function':'span'},0),
]
rows=[]
for name,base,size,kw,expected in plans:
    r=run(name,base,size,**kw);assert r['result']==expected,(name,r,hex(expected));rows.append(r)
assert all(not any(e['stub']=='metadata_span' for e in r['events']) for r in rows[:2])
report={'classification':'isolated controlled replay with explicit stubs; not native success',
        'TZ_sha256':hashlib.sha256(raw).hexdigest(),'metadata_sha256':hashlib.sha256(mdt).hexdigest(),
        'permitted_start':START,'permitted_end_exclusive':END,'metadata_min':lo,'metadata_end':hi,
        'case_count':len(rows),'cases':rows,
        'limitations':['Live secure globals not captured; initialized from the two shipped devcfg images.',
                       'Metadata span, persistent-ledger hashing and logging are explicit stubs.',
                       'Authentication-related instructions are modeled; no secure-monitor entry is replayed.',
                       'An allowed range is not proof of free RAM, safe relocation, ownership or DSP startup.',
                       'G136 is still required to bind the exact live rejection.']}
assert not args.output.exists(), 'Keep prior model evidence; choose a new output path.'
args.output.write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'case_count':len(rows),'all_passed':True,'G134_model_error':hex(rows[0]['result']),
                  'shorter_same_address_error':hex(rows[1]['result']),
                  'permitted_range':[hex(START),hex(END)],'native_DSP_operations':0}))
