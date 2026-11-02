"""Execute unchanged reference I2CDxe ARM64 routines with explicit MMIO models.

This validates reconstructed software behavior, not an electrical bus transfer.
The reference artifact's identity against the running firmware is unproved.
"""
from pathlib import Path
import argparse, hashlib, json, struct
import pefile
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_HOOK_CODE, UC_MEM_WRITE
from unicorn.arm64_const import *

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--image', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
assert not a.output.exists()
raw = a.image.read_bytes()
sha = hashlib.sha256(raw).hexdigest()
assert sha == 'b3aa69541e526a1f53c88c958cc23fe4149d0db648835e35b85b1ce3fdaf1cda'
pe = pefile.PE(data=raw)
assert pe.FILE_HEADER.Machine == 0xaa64 and pe.OPTIONAL_HEADER.ImageBase == 0
image = pe.get_memory_mapped_image()
ARENA, STACK, END, MMIO = 0x30000000, 0x3003fff0, 0x10000000, 0x18000000
REQ, DEV, PLATFORM, BUS, DESC, TIMING, BUFFER = [ARENA + i * 0x1000 for i in range(1, 8)]
saved = [UC_ARM64_REG_X19, UC_ARM64_REG_X20, UC_ARM64_REG_X21, UC_ARM64_REG_X22,
         UC_ARM64_REG_X23, UC_ARM64_REG_X24, UC_ARM64_REG_X25, UC_ARM64_REG_X26,
         UC_ARM64_REG_X27, UC_ARM64_REG_X28, UC_ARM64_REG_X29]
argregs = [UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2]

def put(u, at, fmt, *v):
    u.mem_write(at, struct.pack('<' + fmt, *v))

def word(u, at):
    return struct.unpack('<I', u.mem_read(at, 4))[0]

def setup():
    u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    u.mem_map(0, (len(image) + 4095) & ~4095)
    u.mem_write(0, image)
    u.mem_map(ARENA, 0x40000)
    u.mem_map(END, 4096)
    u.mem_map(MMIO, 0x2000)
    u.reg_write(UC_ARM64_REG_SP, STACK)
    for i, r in enumerate(saved):
        u.reg_write(r, 0x8800000000000000 + i * 256)
    events, boundaries = [], []
    def mem(uc, access, at, size, value, user):
        if MMIO <= at < MMIO + 0x2000:
            assert size == 4
            events.append({'op': 'write' if access == UC_MEM_WRITE else 'read',
                           'offset': hex(at-MMIO), 'value': value if access == UC_MEM_WRITE else word(uc, at)})
    u.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, mem)
    # Only the original driver's OS wait/completion boundaries are stubbed.
    # MMIO contents are supplied by each case. No tested routine is patched.
    def code(uc, pc, size, user):
        if pc in (0x7424, 0x3a14):
            boundaries.append({'routine': hex(pc), 'x1': uc.reg_read(UC_ARM64_REG_X1)})
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))
    u.hook_add(UC_HOOK_CODE, code)
    return u, events, boundaries

def invoke(u, entry, args):
    prior = [u.reg_read(r) for r in saved]
    u.reg_write(UC_ARM64_REG_LR, END)
    for r, v in zip(argregs, args):
        u.reg_write(r, v)
    u.emu_start(entry, END, count=100000)
    assert u.reg_read(UC_ARM64_REG_PC) == END and u.reg_read(UC_ARM64_REG_SP) == STACK
    assert [u.reg_read(r) for r in saved] == prior
    return u.reg_read(UC_ARM64_REG_X0) & 0xffffffff

def request(u, flags=5, length=1, index=0, count=2, mode=0):
    put(u, REQ, 'QQQ', DEV, BUS, DESC)
    put(u, REQ+0x2c, 'H', count)
    put(u, REQ+0x34, 'I', index)
    put(u, DEV, 'Q', PLATFORM)
    put(u, DEV+0x10, 'Q', ARENA+0x9000)
    put(u, DEV+0x30, 'Q', REQ)
    put(u, PLATFORM, 'Q', MMIO)
    put(u, PLATFORM+0x50, 'Q', TIMING)
    put(u, BUS, 'III', 400, 0x55, mode)
    put(u, TIMING, 'III', 400, 400, 0x0b0a1a07)
    put(u, DESC+index*24, 'QIIII', BUFFER, length, flags, 0, 0)

cases = []
for flags, length, mode, expected in [(5,1,0,1),(7,3,0,1),(11,2,0,2),(9,2,0,2),
                                     (1,0,0,4),(2,0,0,7),(0,0,0,6),(4,1,2,9),(8,2,2,10)]:
    u,e,b=setup()
    result=invoke(u,0x368c,[flags,length,mode])
    assert result==expected and not e
    cases.append({'routine':'opcode@368c','flags':flags,'length':length,'mode':mode,'result':result})

for flags,length,index,count,command in [(5,1,0,2,0x0800aa04),(7,3,0,1,0x0800aa00),
                                        (11,2,1,2,0x1000aa00),(9,2,0,2,0x1000aa04)]:
    u,e,b=setup();request(u,flags,length,index,count)
    assert invoke(u,0x37bc,[REQ])==0
    writes=[x for x in e if x['op']=='write']
    assert word(u,MMIO+0x600)==command
    for offset,value in [(0x260,0x7f8fe),(0x264,0xffefe),(0x284,0x7f8fe),(0x288,0xffefe),(0x48,0x71),(0x278,0x00a02c1a)]:
        assert word(u,MMIO+offset)==value
    assert word(u,MMIO+(0x26c if flags&4 else 0x270))==length
    assert word(u,REQ+0x38)==1
    cases.append({'routine':'setup-command@37bc','flags':flags,'length':length,'index':index,'command':hex(command),'writes':writes})

for data in [b'\x00', b'\x00\x01\x00', b'\x00\x02\x00', bytes(range(1,5)), bytes(range(1,8))]:
    u,e,b=setup();request(u,7,len(data),0,1)
    # FIFO helper receives the request substructure beginning at +8.
    put(u,REQ+0x30,'I',0);put(u,REQ+0x34,'I',0)
    put(u,MMIO+0xe24,'I',0x201029e4);put(u,MMIO+0x80c,'I',1)
    u.mem_write(BUFFER,data)
    invoke(u,0x349c,[MMIO,REQ+8])
    packed=[x['value'] for x in e if x['op']=='write' and x['offset']=='0x700']
    expected=[int.from_bytes(data[i:i+4].ljust(4,b'\0'),'little') for i in range(0,len(data),4)]
    assert packed==expected and word(u,REQ+0x30)==len(data)
    cases.append({'routine':'tx-fifo@349c','data':data.hex(),'words':packed})

for n in (1,2,3,4):
    u,e,b=setup();request(u,11,n,0,1)
    put(u,REQ+0x30,'I',0);put(u,REQ+0x34,'I',0)
    put(u,MMIO+0x804,'I',0x80000001|(n<<28));put(u,MMIO+0x780,'I',0x78563412)
    invoke(u,0x3590,[MMIO,REQ+8])
    value=bytes(u.mem_read(BUFFER,n))
    assert value==bytes.fromhex('12345678')[:n] and word(u,REQ+0x30)==n
    assert len([x for x in e if x['op']=='read' and x['offset']=='0x780'])==1
    cases.append({'routine':'rx-fifo@3590','length':n,'bytes':value.hex()})

for cancel,abort in [(True,False),(False,True),(False,False)]:
    u,e,b=setup();request(u)
    # Force NACK error. The explicit device model supplies only the requested
    # completion acknowledgments. Completion handoff is stubbed above.
    put(u,MMIO+0x610,'I',1<<10)
    def ack(uc,access,at,size,value,user):
        if at==MMIO+0x604:
            if value==4 and cancel:put(uc,MMIO+0x610,'I',(1<<10)|(1<<4))
            if value==2 and abort:put(uc,MMIO+0x610,'I',(1<<10)|(1<<5))
    u.hook_add(UC_HOOK_MEM_WRITE,ack)
    invoke(u,0x3aac,[DEV])
    writes=[(x['offset'],x['value']) for x in e if x['op']=='write']
    assert ('0x604',4) in writes
    assert (('0x604',2) in writes)==(not cancel)
    # Original firmware also force-defaults after cancel timeout. Record this
    # observation; G102 must not silently copy that reset into its contract.
    assert (('0x20',1) in writes)==(not cancel)
    cases.append({'routine':'error@3aac','cancel_ack':cancel,'abort_ack':abort,'writes':writes,'boundaries':b})

out={'passed':True,'cases':cases,'case_count':len(cases),'artifact_sha256':sha,
     'original_code_unmodified':True,'native_operations':0,
     'modeled_boundaries':['fixed MMIO register contents and completion transitions',
                           'firmware delay@7424','request completion@3a14'],
     'limits':['Reference artifact identity against running firmware remains unproved.',
               'Original ARM64 execution establishes software semantics, not electrical gauge responses.',
               'The ordinary TX FIFO helper uses HW_PARAM0; hub depth must come from its dedicated contract.',
               'Force-default behavior is observed but not adopted for the forthcoming diagnostic.']}
a.output.write_text(json.dumps(out,indent=2)+'\n')
print(json.dumps({'passed':True,'cases':len(cases),'original_code_unmodified':True,'native_operations':0}))
