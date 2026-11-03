#!/usr/bin/env python3
"""Offline only; caller supplies pinned unsigned NC OEM derivative. Default inert."""
import argparse,hashlib,json,pathlib,struct,subprocess
BASE='927bf9450f462607435d616c0d2f00884f6689bcd2c395bcc949896ff93c8ee0'
START,END,EPILOGUE=0x14e09c,0x14e1b4,0x14e1b4
D=pathlib.Path(__file__).resolve().parent
sha=lambda b:hashlib.sha256(b).hexdigest()
def need(v,m):
 if not v:raise ValueError(m)
def sext(v,n):return v-(1<<n) if v&(1<<(n-1)) else v
def pe_offset(b,rva):
 pe=struct.unpack_from('<I',b,0x3c)[0];need(b[pe:pe+4]==b'PE\0\0','PE required');machine,n=struct.unpack_from('<HH',b,pe+4);size=struct.unpack_from('<H',b,pe+20)[0]
 need(machine==0xaa64 and struct.unpack_from('<H',b,pe+24)[0]==0x20b,'ARM64 PE32+ required')
 for i in range(n):
  at=pe+24+size+i*40;vs,va,raw,off=struct.unpack_from('<IIII',b,at+8)
  if va<=rva<va+min(vs,raw):return off+rva-va
 raise ValueError('RVA not uniquely file backed')
def elf_text(b):
 need(b[:6]==b'\x7fELF\x02\x01','ELF64 little endian required');shoff=struct.unpack_from('<Q',b,40)[0];ents,n,idx=struct.unpack_from('<HHH',b,58);hs=[struct.unpack_from('<IIQQQQIIQQ',b,shoff+i*ents)for i in range(n)];st=hs[idx];names=b[st[4]:st[4]+st[5]];text=[]
 for h in hs:
  need(not(h[1]in(4,9)and h[5]),'Unresolved output relocations refused')
  name=names[h[0]:].split(b'\0',1)[0]
  if name==b'.text':text.append((h[3],b[h[4]:h[4]+h[5]]))
 need(len(text)==1 and text[0][0]==START,'Exact linked body address required');return text[0][1]
def validate_body(b):
 need(len(b)==264,'58instructions+32Btable required');words=struct.unpack('<58I',b[:232]);regs=list(struct.unpack('<8I',b[232:]));need(regs==[0x1b85400,0x1b85404,0x1b85408,0x1b8540c,0x1b85010,0x1b85014,0x1b8506c,0x1b85070],'Exact fixed register allowlist required')
 branches=[];bl=[];adr=[];adrp=[]
 for i,w in enumerate(words):
  pc=START+4*i;target=None;kind=None
  if w&0xfc000000==0x94000000:target=pc+sext(w&0x3ffffff,26)*4;kind='BL';bl.append(target)
  elif w&0xfc000000==0x14000000:target=pc+sext(w&0x3ffffff,26)*4;kind='B'
  elif w&0xff000010==0x54000000:target=pc+sext((w>>5)&0x7ffff,19)*4;kind='B.cond'
  elif w&0x7e000000==0x34000000:target=pc+sext((w>>5)&0x7ffff,19)*4;kind='CBZ/CBNZ'
  elif w&0x9f000000==0x10000000:adr.append(pc+sext(((w>>5)&0x7ffff)*4+((w>>29)&3),21))
  elif w&0x9f000000==0x90000000:adrp.append((pc&~0xfff)+(sext(((w>>5)&0x7ffff)*4+((w>>29)&3),21)<<12))
  if target is not None:
   need(target%4==0,'Unaligned branch')
   if kind!='BL':need(START<=target<START+232 or target==EPILOGUE,'Branch escapes instructions/epilogue')
   branches.append(dict(pc=hex(pc),kind=kind,target=hex(target)))
 need(bl==[0x1eb588] and adr==[START+232] and adrp==[0x397000],'Exact BL/ADR/ADRP targets required')
 need(words[-1]&0xfc000000==0x14000000,'No fallthrough into table')
 return dict(instructions=58,table_bytes=32,padding_bytes=16,registers=[hex(x)for x in regs],branches=branches,BL_targets=[hex(x)for x in bl],ADR_table=hex(adr[0]),ADRP_page=hex(adrp[0]),unresolved_relocations=0)
def main():
 p=argparse.ArgumentParser();p.add_argument('--build-offline',action='store_true');p.add_argument('--base',type=pathlib.Path);p.add_argument('--out',type=pathlib.Path);p.add_argument('--clang',default='/usr/bin/clang');p.add_argument('--ld',default='ld.lld');a=p.parse_args()
 if not a.build_offline:print('INERT: no build/read/patch');return
 need(a.base is not None and a.out is not None,'Explicit base and new output directory required');b=a.base.read_bytes();need(sha(b)==BASE,'Exact unsigned NC base required');need(b[pe_offset(b,0x7dbc):pe_offset(b,0x7dbc)+4]==bytes.fromhex('08008052'),'NC MOV0 must remain present')
 a.out.mkdir(exist_ok=False);src=D/'getter.S';o=a.out/'getter.o';elf=a.out/'getter.elf'
 compile_cmd=[a.clang,'-target','aarch64-none-elf','-c',str(src),'-o',str(o)];link_cmd=[a.ld,'-m','aarch64elf','--no-relax','-Ttext='+hex(START),'--entry=body','--defsym=RVA_397000=0x397000','--defsym=RVA_1eb588=0x1eb588','--defsym=ORIGINAL_EPILOGUE_14e1b4=0x14e1b4',str(o),'-o',str(elf)]
 subprocess.run(compile_cmd,check=True);subprocess.run(link_cmd,check=True);body=elf_text(elf.read_bytes());flow=validate_body(body);payload=body+bytes.fromhex('1f2003d5')*4;off=pe_offset(b,START);need(pe_offset(b,END-1)==off+279,'Contiguous exact .text mapping required');c=bytearray(b);c[off:off+280]=payload;c=bytes(c);diff=[i for i,(x,y)in enumerate(zip(b,c))if x!=y];need(diff and len(c)==len(b) and all(off<=i<off+280 for i in diff),'Only approved280B body may change')
 for lo,hi in [(0x14e078,START),(END,0x14e1d4),(0x32c4c8,0x32c4e8),(0x433100,0x433108),(0x1eb588,0x1eb83c),(0x7dbc,0x7dc0)]:
  aa,bb=pe_offset(b,lo),pe_offset(b,hi-1)+1;need(c[aa:bb]==b[aa:bb],'Preserved frame/unwind/native/NC region changed')
 (a.out/'getter-body.bin').write_bytes(payload);target=a.out/'qcwlanhmt8380-G1340-unsigned.sys';target.write_bytes(c)
 manifest=dict(schema='G1340-offline-getter-patch/1',base_unsigned_NC_sha256=sha(b),candidate_unsigned_sha256=sha(c),candidate_bytes=len(c),source_sha256=sha(src.read_bytes()),patch_script_sha256=sha(pathlib.Path(__file__).read_bytes()),body_sha256=sha(payload),RVA_begin=hex(START),RVA_end_exclusive=hex(END),file_offset=off,different_bytes=len(diff),changed_offsets=diff,old_body_sha256=sha(b[off:off+280]),flow=flow,prologue_epilogue_unwind_GS_unchanged=True,HAL_native_helper_unchanged=True,NC_MOV0_unchanged=True,compile_command=compile_cmd,link_command=link_cmd,signature_qualified=False,runtime_approved=False,target_calls=0)
 (a.out/'PATCH-MANIFEST.json').write_text(json.dumps(manifest,indent=2)+'\n');print(json.dumps(dict(candidate_unsigned_sha256=sha(c),different_bytes=len(diff),file_offset=off,output=str(target))))
if __name__=='__main__':main()
