#!/usr/bin/env python3
"""Offline ARM64 semantic regression; requires caller-provided Unicorn2 Python module."""
import argparse, hashlib, json, pathlib, random, struct
import patch

def semantic():
 from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM
 from unicorn.arm64_const import UC_ARM64_REG_X0,UC_ARM64_REG_X19,UC_ARM64_REG_X28,UC_ARM64_REG_NZCV
 # X29/X30 are nonconsecutive in Unicorn constants; use named registers.
 import unicorn.arm64_const as regs
 cases=[0,1,2,3,4,5,31,32,0x7fffffff,0x80000000,0xfffffffe,0xffffffff]
 rng=random.Random(1349);cases += [rng.getrandbits(32) for _ in range(256)]
 code=patch.BODY+patch.branch(patch.CAVE+20,patch.RETURN)
 count=0
 for p in cases:
  for flags in range(16):
   u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.mem_map(0x1d7000,0x1000);u.mem_map(0x400000,0x1000)
   u.mem_write(patch.SITE,patch.branch(patch.SITE,patch.CAVE));u.mem_write(patch.CAVE,code)
   before=bytes(rng.getrandbits(8) for _ in range(64));u.mem_write(0x400000,before)
   saved={}
   for n in range(31):
    reg=getattr(regs,'UC_ARM64_REG_X'+str(n));value=rng.getrandbits(64)
    if n==19:value=0x400000
    if n==28:value=p
    u.reg_write(reg,value);saved[n]=value
   notify=u.reg_read(getattr(regs,'UC_ARM64_REG_X8'))&0xffffffff
   u.reg_write(UC_ARM64_REG_NZCV,flags<<28);u.emu_start(patch.SITE,patch.RETURN,count=7)
   assert u.reg_read(regs.UC_ARM64_REG_PC)==patch.RETURN
   expected=bytearray(before);struct.pack_into('<II',expected,16,2 if p==1 else p,notify)
   assert bytes(u.mem_read(0x400000,64))==expected
   assert u.reg_read(UC_ARM64_REG_NZCV)==flags<<28
   for n,value in saved.items():
    if n!=9:assert u.reg_read(getattr(regs,'UC_ARM64_REG_X'+str(n)))==value,(p,n)
   count+=1
 return count

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--base',type=pathlib.Path);a=ap.parse_args()
 count=semantic();result={'ARM64_cases':count,'all_GPR_except_dead_X9_unchanged':True,'NZCV_unchanged':True,'only_original_8byte_pair_changed':True}
 if a.base:
  data=a.base.read_bytes();out,sites,diff=patch.derive(data)
  try:patch.derive(bytes([data[0]^1])+data[1:])
  except ValueError:pass
  else:raise AssertionError('wrong base accepted')
  result.update(candidate_sha256=hashlib.sha256(out).hexdigest(),candidate_bytes=len(out),changed_bytes=len(diff),bounded_two_spans=True,wrong_base_rejected=True)
 print(json.dumps(result,indent=2))
if __name__=='__main__':main()
