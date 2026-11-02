"""CPU mock tests only. Production SMC is intercepted BEFORE instruction emulation."""
from pathlib import Path
import subprocess,struct,hashlib,json,sys
H=Path(__file__).resolve().parents[1];R=H.parents[1];B=H/'tests/build';B.mkdir(exist_ok=True)
# Reuse retained local Unicorn; no installation/network/target access.
sys.path.insert(0,str(R/'work/maintenance-G18/gpio-G22/private/venv/lib/python3.9/site-packages'))
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn.arm64_const import UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3,UC_ARM64_REG_X4,UC_ARM64_REG_X5,UC_ARM64_REG_X6,UC_ARM64_REG_X7,UC_ARM64_REG_X18,UC_ARM64_REG_X19,UC_ARM64_REG_X20,UC_ARM64_REG_X29,UC_ARM64_REG_X30,UC_ARM64_REG_SP,UC_ARM64_REG_PC
C='/usr/bin/clang';state=B/'state';cmd=[C,'-std=c11','-O1','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-fno-omit-frame-pointer','-I'+str(H/'source'),str(H/'source/query_state.c'),str(H/'tests/state_actor.c'),'-o',str(state)];subprocess.run(cmd,check=True,capture_output=True);s=subprocess.run([str(state)],check=True,capture_output=True,text=True)
obj=B/'smc_fast_info.obj';subprocess.run([C,'--target=aarch64-pc-windows-msvc','-c',str(H/'source/smc_fast_info.S'),'-o',str(obj)],check=True,capture_output=True)
b=obj.read_bytes();machine,n,_,_,_,optional,_=struct.unpack_from('<HHIIIHH',b,0);assert machine==0xaa64;sects={}
for i in range(n):
 p=20+optional+40*i;name=b[p:p+8].rstrip(b'\0').decode();size,off=struct.unpack_from('<II',b,p+16);sects[name]=b[off:off+size]
text=sects['.text'];assert '.pdata' in sects and '.xdata' in sects and text.count(bytes.fromhex('030000d4'))==1
regs=[UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3,UC_ARM64_REG_X4,UC_ARM64_REG_X5,UC_ARM64_REG_X6,UC_ARM64_REG_X7]
profile=[0xc2000601,1,0x02000c1b,0,0,0,0,0];cases=[]
def actor(name,returns):
 u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);code,stop,frame,stack=0x100000,0x200000,0x300000,0x400000
 for a,size in [(code,0x1000),(frame,0x1000),(stack,0x20000)]:u.mem_map(a,size)
 u.mem_write(code,text);sp=stack+0x1ff00;u.reg_write(UC_ARM64_REG_SP,sp);u.reg_write(UC_ARM64_REG_X30,stop);u.reg_write(UC_ARM64_REG_X0,frame)
 saved={UC_ARM64_REG_X18:0x18181818,UC_ARM64_REG_X19:0x19191919,UC_ARM64_REG_X20:0x20202020,UC_ARM64_REG_X29:0x29292929}
 for r,v in saved.items():u.reg_write(r,v)
 inputs=[]
 def hook(uc,pc,size,data):
  if uc.mem_read(pc,4)==bytes.fromhex('030000d4'):
   # This skips the ONLY SMC instruction; no secure monitor exists in this emulator.
   v=[uc.reg_read(r) for r in regs];inputs.append(v);i=len(inputs)-1;assert i<len(returns),'unexpected replay'
   assert v==(profile if i==0 else returns[i-1]),'lost returned register/x6 continuation state'
   for r,x in zip(regs,returns[i]):uc.reg_write(r,x)
   uc.reg_write(UC_ARM64_REG_PC,pc+4)
 u.hook_add(UC_HOOK_CODE,hook);u.emu_start(code,stop,count=100000);assert u.reg_read(UC_ARM64_REG_PC)==stop
 got=list(struct.unpack('<8Q3Q',u.mem_read(frame,88)));assert got[:8]==returns[-1];assert got[8:]==[len(returns),len(returns),len(returns)-1];assert inputs[0]==profile
 assert u.reg_read(UC_ARM64_REG_SP)==sp
 for r,v in saved.items():assert u.reg_read(r)==v,'Windows preserved register changed'
 cases.append({'name':name,'mock_transitions':len(inputs),'final_raw':got[:8],'entries_returns_interrupts':got[8:],'x6_resume_and_nonvolatiles_preserved':True})
actor('available',[[0,1,0x22,0x33,0x44,0x55,0x66,0x77]])
actor('unavailable',[[0,0,0,0,0,0,0,0]])
actor('interrupted_then_complete',[[1,0x11,0x22,0x33,0x44,0x55,0xa6a6,0x77],[0,1,2,3,4,5,6,7]])
actor('two_interruptions_then_complete',[[1,11,12,13,14,15,16,17],[1,21,22,23,24,25,26,27],[0,1,32,33,34,35,36,37]])
for code,name in [(0xfffffffffffffff4,'busy_no_retry'),(0xffffffffffffffff,'unsupported_no_fallback'),(2,'WAITQ_sleep_return'),(3,'WAITQ_wake_return'),(7,'unknown_positive_return'),(0x100000000,'nonzero_highbits_not_success'),(0x100000001,'nonexact1_not_resume'),(0xfffffff4,'zero_extended_busy_no_retry'),(0xffffffff,'zero_extended_unsupported_no_fallback'),(0xfffffffc,'zero_extended_not_supported_no_fallback'),(0x1fffffff4,'malformed_upper_bits_no_retry'),(0xffffffff00000001,'noncanonical_one_no_resume')]:actor(name,[[code,1,2,3,4,5,6,7]])
report={'schema':'g1268-cpu-mock-validation/1','monitor_calls':0,'target_operations':0,'scope':'actual production state C and COFF .text emulator; each SMC skipped before execution; no EFI/SYS link or runtime qualification','state_actor':s.stdout.strip(),'production_thunk_coff_sha256':hashlib.sha256(b).hexdigest(),'production_thunk_text_sha256':hashlib.sha256(text).hexdigest(),'SEH_pdata_xdata_present':True,'thunk_cases':cases,'source_pins':{str(p.relative_to(H)):hashlib.sha256(p.read_bytes()).hexdigest() for p in [H/'source/query_state.c',H/'source/query_protocol.h',H/'source/smc_fast_info.S',H/'tests/state_actor.c',Path(__file__)]}}
(H/'TEST-RESULT.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
