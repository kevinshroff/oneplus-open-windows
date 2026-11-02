"""Bound the captured IC-info layout, then compare with unchanged vendor conversion.

This reads saved files and executes only a local CPU converter; no phone calls.
"""
from pathlib import Path
import argparse,hashlib,json,re,subprocess
p=argparse.ArgumentParser();p.add_argument('--inputs',type=Path,required=True);p.add_argument('--block',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True)
root=a.inputs/'reference-goodix';h=root/'GT9966-goodix_brl_core.h';c=root/'GT9966-goodix_brl_core.c';sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();assert sha(h)=='4605c36d099607bfdf912085171b1c8c049ab01cf8762c6446bfee13b9c5eab3'and sha(c)=='f0e09004861d89392f163709a64a4effe2da0b7831a2d20f57b41fcbff63674a';head=h.read_text();source=c.read_text()
macros={k:int(re.search(r'^#define\s+'+k+r'\s+(\d+)',head,re.M)[1])for k in['MAX_SCAN_RATE_NUM','MAX_SCAN_FREQ_NUM','MAX_FREQ_NUM_STYLUS']};assert list(macros.values())==[5,5,8]
names=['goodix_ic_info_version','goodix_ic_info_feature','goodix_ic_info_param','goodix_ic_info_misc','goodix_ic_info'];structs={n:re.search(r'struct '+n+r'\s*\{.*?\n\};',head,re.S)[0]for n in names}
def fields(n):
 s=re.sub(r'/\*.*?\*/','',structs[n],flags=re.S);out=[]
 for width,name,count in re.findall(r'\bu(8|16|32)\s+(\w+)(?:\[(\w+)\])?\s*;',s):
  out.append((int(width)//8,name,macros[count]if count in macros else int(count)if count else 1))
 return out
V,F,P,M=(fields(n)for n in names[:4]);assert sum(w*n for w,k,n in V)==16 and sum(w*n for w,k,n in F)==10 and sum(w*n for w,k,n in M)==114 and sum(w*n for w,k,n in P)==65

def parse(data):
 if len(data)<153 or len(data)>1023 or int.from_bytes(data[:2],'little')!=len(data):raise ValueError('invalid length')
 if(sum(data[:-2])&65535)!=int.from_bytes(data[-2:],'little'):raise ValueError('bad checksum')
 cursor=2;wire_end=len(data)-2;expected=bytearray(data[:28]);result={'length':len(data)};sections={}
 def take(n):
  nonlocal cursor
  if cursor+n>wire_end:raise ValueError('layout exceeds checksum boundary')
  b=data[cursor:cursor+n];cursor+=n;return b
 def fixed(schema):
  d={}
  for width,name,count in schema:
   b=take(width*count);v=[int.from_bytes(b[i:i+width],'little')for i in range(0,len(b),width)];d[name]=v[0]if count==1 else v
  return d
 sections['version']=fixed(V);sections['feature']=fixed(F);parm={};param_bytes=bytearray()
 for name in['drv_num','sen_num','button_num','force_num']:
  b=take(1);parm[name]=b[0];param_bytes+=b
 for label,cap in[('active_scan_rate',5),('mutual_freq',5),('self_tx_freq',5),('self_rx_freq',5),('stylus_freq',8)]:
  count=take(1)[0]
  if count>cap:raise ValueError('count exceeds source capacity: '+label)
  b=take(count*2);parm[label+'_num']=count;parm[label]=[int.from_bytes(b[i:i+2],'little')for i in range(0,len(b),2)];param_bytes+=bytes([count])+b+bytes((cap-count)*2)
 assert len(param_bytes)==65;expected+=param_bytes;sections['parm']=parm;misc_at=cursor;sections['misc']=fixed(M);expected+=data[misc_at:cursor];assert len(expected)==207
 for field in['cmd_addr','fw_buffer_addr','touch_data_addr']:
  if not sections['misc'][field]:raise ValueError('zero key address: '+field)
 result.update(sections,known_wire_bytes=cursor,known_struct_bytes=len(expected),uninterpreted_extension_bytes=wire_end-cursor,extension_hex=data[cursor:wire_end].hex(),misc_wire_offset=misc_at)
 return result,bytes(expected)

block=a.block.read_bytes();result,expected=parse(block);tests=1
for n in range(len(block)):
 try:parse(block[:n])
 except ValueError:tests+=1
 else:raise AssertionError(('truncation accepted',n))
# Recompute checksums so count-bound tests reach the parser, not the checksum gate.
count_cursor=32
for label,cap in[('active_scan_rate',5),('mutual_freq',5),('self_tx_freq',5),('self_rx_freq',5),('stylus_freq',8)]:
 d=bytearray(block);old=d[count_cursor];d[count_cursor]=cap+1;d[-2:]=(sum(d[:-2])&65535).to_bytes(2,'little')
 try:parse(d)
 except ValueError:tests+=1
 else:raise AssertionError(('oversized count accepted',label))
 count_cursor+=1+old*2
short=bytearray(block[:153]);short[:2]=(153).to_bytes(2,'little');short[-2:]=(sum(short[:-2])&65535).to_bytes(2,'little')
try:parse(short)
except ValueError:tests+=1
else:raise AssertionError('truncated misc accepted')
start=source.index('static int convert_ic_info(');i=source.index('{',start)+1;depth=1
while depth:depth+=(source[i]=='{')-(source[i]=='}');i+=1
body=source[start:i]
prefix='''#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;typedef uint16_t __le16;
#define TPD_INFO(...) ((void)0)
#define le16_to_cpu(x) (x)
#define le32_to_cpu(x) (x)
#define LE16_TO_CPU(x) (x=le16_to_cpu(x))
#define LE32_TO_CPU(x) (x=le32_to_cpu(x))
static u16 le16_to_cpup(const void*p){const u8*b=p;return (u16)((u16)b[0]|((u16)b[1]<<8));}
'''+''.join('#define '+k+' '+str(v)+'\n'for k,v in macros.items())+'#pragma pack(push,1)\n'+'\n'.join(structs.values())+'\n#pragma pack(pop)\n'
fixture='static const u8 Block[]={'+','.join(map(str,block))+'};\n'
main='''int main(void){struct goodix_ic_info info;uint16_t order=1;assert(*(uint8_t*)&order==1);memset(&info,0,sizeof(info));assert(sizeof(info)==207);assert(!convert_ic_info(&info,Block));assert(fwrite(&info,1,sizeof(info),stdout)==sizeof(info));return 0;}\n'''
f=a.output/'vendor-converter.c';f.write_text(prefix+body+'\n'+fixture+main);exe=a.output/'vendor-converter';q=subprocess.run(['clang','-std=c11','-O1','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(f),'-o',str(exe.resolve())],capture_output=True,text=True);assert not q.returncode,q.stderr
q=subprocess.run([str(exe.resolve())],capture_output=True);assert not q.returncode and not q.stderr,(q.returncode,q.stderr.decode(errors='replace'));assert q.stdout==expected,'Python bounded layout and unchanged vendor conversion differ';(a.output/'converted-207.bin').write_bytes(q.stdout)
result.update(passed=True,bounds_cases=tests,original_vendor_converter_executed_unchanged=True,all207_output_bytes_match_independent_bounded_parser=True,ASan_UBSan=True,block_sha256=sha(a.block),source_C_sha256=sha(c),source_H_sha256=sha(h),original_converter_body_sha256=hashlib.sha256(body.encode()).hexdigest(),device_addresses_are_SPI_bus_addresses_not_CPU_MMIO=True,native_commands_submitted=0,limits=['Linux byte-order helpers are explicit local bytewise little-endian/identity operations.','The trailing extension is retained without inventing semantics.','This interprets a saved checksummed block; it performs no new physical read, report transfer or configuration write.'])
(a.output/'decoded.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
