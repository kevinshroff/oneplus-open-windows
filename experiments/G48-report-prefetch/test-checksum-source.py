"""Compare the actual G48 checksum fragment with the unchanged stock function."""
from pathlib import Path
import argparse,hashlib,json,re,subprocess
p=argparse.ArgumentParser();p.add_argument('--inputs',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True);W=Path(__file__).resolve().parent;vendor=a.inputs/'reference-goodix/GT9966-goodix_brl_core.c';assert hashlib.sha256(vendor.read_bytes()).hexdigest()=='f0e09004861d89392f163709a64a4effe2da0b7831a2d20f57b41fcbff63674a';s=vendor.read_text();start=s.index('int checksum_cmp(');i=s.index('{',start)+1;d=1
while d:d+=(s[i]=='{')-(s[i]=='}');i+=1
original=s[start:i];touch=(W/'g48_touch.c').read_text();m=re.search(r'r->InfoLength=.*?if\(!r->FullBlockChecksumValid\)r->Code=7;',touch);assert m;fragment=m[0]
code='''#include "g48_touch.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
typedef uint8_t u8;typedef uint32_t u32;
enum {CHECKSUM_MODE_U8_LE=0,CHECKSUM_MODE_U16_LE=1};
'''+original+'\nstatic void Actual(G48_TOUCH_RESULT*r){'+fragment+'}\n'+r'''
static void Check(const uint8_t*data,int expected){G48_TOUCH_RESULT r;int reference;memset(&r,0,sizeof(r));memcpy(r.Rx+8,data,242);Actual(&r);reference=(data[0]==242&&data[1]==0&&!checksum_cmp(data,242,CHECKSUM_MODE_U8_LE));assert(reference==expected&&r.FullBlockChecksumValid==(uint32_t)expected&&r.HeaderLengthValid==(uint32_t)(data[0]==242&&data[1]==0)&&r.Code==(expected?0u:7u));}
static void Seal(uint8_t*d){unsigned sum=0,i;for(i=0;i<240;i++)sum+=d[i];d[240]=(uint8_t)sum;d[241]=(uint8_t)(sum>>8);}
int main(void){uint8_t data[242];unsigned seed,i,bit,cases=0;const unsigned lens[]={0,1,28,152,153,241,242,243,1023,1024,65535};
 for(seed=1;seed<=3;seed++){for(i=0;i<240;i++)data[i]=(uint8_t)(i*37+seed*19);data[0]=242;data[1]=0;Seal(data);Check(data,1);cases++;
  for(i=0;i<242;i++)for(bit=0;bit<8;bit++){data[i]^=(uint8_t)(1u<<bit);Check(data,0);data[i]^=(uint8_t)(1u<<bit);cases++;}
 }
 for(i=0;i<sizeof(lens)/sizeof(lens[0]);i++){memset(data,0,sizeof(data));data[0]=(uint8_t)lens[i];data[1]=(uint8_t)(lens[i]>>8);Seal(data);Check(data,lens[i]==242);cases++;}
 printf("{\"passed\":true,\"cases\":%u,\"actual_G48_fragment_executed_unchanged\":true,\"stock_checksum_function_executed_unchanged\":true,\"all_single_payload_bit_errors_refused\":true,\"only_fixed242_byte_length_accepted\":true}\n",cases);return 0;}
'''
f=a.output/'checksum.c';f.write_text(code);exe=a.output/'checksum';q=subprocess.run(['clang','-std=c11','-O1','-Wall','-Wextra','-Werror','-Wno-sign-compare','-fsanitize=address,undefined','-I',str(W),str(f),'-o',str(exe.resolve())],capture_output=True,text=True);assert not q.returncode,q.stderr
q=subprocess.run([str(exe.resolve())],capture_output=True,text=True);assert not q.returncode and not q.stderr,(q.returncode,q.stdout,q.stderr);r=json.loads(q.stdout);r.update(ASan_UBSan=True,Touch_source_sha256=hashlib.sha256((W/'g48_touch.c').read_bytes()).hexdigest(),vendor_sha256=hashlib.sha256(vendor.read_bytes()).hexdigest(),original_function_sha256=hashlib.sha256(original.encode()).hexdigest(),actual_fragment_sha256=hashlib.sha256(fragment.encode()).hexdigest(),native_commands_submitted=0,limits=['All data are synthetic CPU fixtures. Physical contents and checksum require a separate native capture.'])
(a.output/'tests.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r))
