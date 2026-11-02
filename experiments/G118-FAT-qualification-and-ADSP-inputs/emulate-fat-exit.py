"""Qualify the installed FAT pre-ExitBootServices read-only admission guard."""
from pathlib import Path
import argparse,json,hashlib,struct
import pefile
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_BLOCK
from unicorn.arm64_const import *
p=argparse.ArgumentParser(description=__doc__)
for n in ['image','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();assert not a.output.exists();raw=a.image.read_bytes();sha=lambda b:hashlib.sha256(b).hexdigest();assert sha(raw)=='896d1eee70e60c0eca53a2405bf8b11bf95d89108cd41aabb6ab86b631fffabd';im=pefile.PE(data=raw).get_memory_mapped_image();ARENA,END=0x30000000,0x10000000;rows=[]
def run(name,ro=False,started=True,signature=True,disk_error=False,lock_busy=False,flush_error=False):
 u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.mem_map(0,(len(im)+4095)&~4095);u.mem_write(0,im);u.mem_map(ARENA,0x20000);u.mem_map(END,4096);u.reg_write(UC_ARM64_REG_CPACR_EL1,3<<20);v=ARENA+0x1000;u.mem_write(v,struct.pack('<Q',0x76746166 if signature else 0));u.mem_write(v+0x10,bytes([int(started),int(disk_error)]));u.mem_write(v+0x44,bytes([int(ro)]));events=[];blocks=0
 def ret(x=0):u.reg_write(UC_ARM64_REG_X0,x);u.reg_write(UC_ARM64_REG_PC,u.reg_read(UC_ARM64_REG_LR))
 def hook(cpu,pc,size,user):
  if pc==0x3b94:events.append('modeled lock');ret(((1<<63)|6)if lock_busy else 0)
  elif pc==0x6180:assert u.reg_read(UC_ARM64_REG_X0)==v and u.reg_read(UC_ARM64_REG_X1)==0;events.append('modeled dirty-cache flush boundary');ret(((1<<63)|7)if flush_error else 0)
  elif pc==0x3c14:events.append('modeled unlock');ret()
  elif pc==0x174c:ret(0)
  else:raise AssertionError(hex(pc))
 for pc in [0x3b94,0x6180,0x3c14,0x174c]:u.hook_add(UC_HOOK_CODE,hook,begin=pc,end=pc)
 def codecheck(cpu,pc,size,user):
  nonlocal blocks
  assert bytes(u.mem_read(pc,size))==im[pc:pc+size];blocks+=1
 u.hook_add(UC_HOOK_BLOCK,codecheck,begin=0x1000,end=len(im)-1);u.reg_write(UC_ARM64_REG_SP,ARENA+0x1f000);u.reg_write(UC_ARM64_REG_LR,END);u.reg_write(UC_ARM64_REG_X0,ARENA+0x8000);u.reg_write(UC_ARM64_REG_X1,v);u.emu_start(0x3c4c,END,count=10000);assert u.reg_read(UC_ARM64_REG_PC)==END;flush=not ro and started and signature and not disk_error and not lock_busy;assert ('modeled dirty-cache flush boundary'in events)==flush;assert bytes(u.mem_read(v+0x4fd0,1))==bytes([int(flush)]);assert not ro or not events
 rows.append({'case':name,'readonly':ro,'started':started,'signature_valid':signature,'disk_error':disk_error,'modeled_lock_busy':lock_busy,'modeled_flush_error':flush_error,'original_code_blocks_verified':blocks,'events':events,'actual_pre_exit_flag':int(flush),'native_operations':0})
run('read-only skips lock and flush',ro=True);run('writable reaches flush boundary');run('not-started skips flush',started=False);run('invalid signature skips flush',signature=False);run('disk-error skips flush',disk_error=True);run('busy lock skips flush',lock_busy=True);run('flush error still records pre-exit',flush_error=True)
x={'passed':True,'cases':len(rows),'Fat_PE_sha256':sha(raw),'original_exit_callback_executed':True,'readonly_admission_skips_flush_boundary':True,'models':['lock bookkeeping','dirty-cache flush callee boundary','log predicate'],'limits':['This qualifies the read-only guard only; the actual flush callee and full filesystem lifecycle are not executed.','No read-only media policy is installed natively by these tests.','Native preflight must guard every source write path; no native boot or DSP start occurs.'],'native_operations':0,'results':rows};a.output.write_text(json.dumps(x,indent=2)+'\n');print(json.dumps({k:v for k,v in x.items()if k not in ['results','models','limits']}))
