"""Bind the masked M80 rule to pinned source, native evidence and the actual guard."""
from pathlib import Path
import argparse,hashlib,json,re,subprocess
p=argparse.ArgumentParser();p.add_argument('--inputs',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True);W=Path(__file__).resolve().parent;sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
b=json.loads((a.inputs/'spi-G27/source-binding.json').read_text());h=a.inputs/'bus-G24/private/qcom-geni-se.h';assert sha(h)==b['files']['bus-G24/private/qcom-geni-se.h']['sha256']
head=h.read_text();assert re.search(r'^#define M_RX_IRQ_EN\s+BIT\(7\)',head,re.M)
native=a.inputs/'recovery-G44/native-qualification.json';n=json.loads(native.read_text());t=n['recovery']['touch'];assert not n['safe_exit_verified']and n['recovery']['transaction_count']==0
assert [x for x in t['trace']if x['kind']==2]==[{'address':'0xa90648','kind':2,'value':0x0c000000},{'address':'0xa90618','kind':2,'value':0x80}]
assert t['trace'][-1]=={'address':'0xa90610','kind':1,'value':0x80}and t['trace'][-4]=={'address':'0xa90640','kind':1,'value':0}
s=(W/'g50_engine.c').read_text();m=re.search(r'^static int Guard\(',s,re.M);assert m;i=s.index('{',m.end())+1;depth=1
while depth:depth+=(s[i]=='{')-(s[i]=='}');i+=1
body=s[m.start():i];arrays='\n'.join(re.search(r'static const uint32_t '+name+r'\[10\]=.*?;',s,re.S).group()for name in['Guards','Masks'])
source='''#include "g50_engine.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static uint32_t Values[10],Enable;static unsigned Reads;
'''+arrays+'''
static int Read(const G50_ENGINE_IO*io,G50_ENGINE_RESULT*r,uint32_t at,uint32_t*out){unsigned i;(void)io;(void)r;Reads++;if(at==0xa90614){*out=Enable;return 1;}for(i=0;i<10;i++)if(at==Guards[i]){*out=Values[i];return 1;}return 0;}
'''+body+'''
int main(void){G50_ENGINE_IO io={0};G50_ENGINE_RESULT r={0};uint32_t out[10];unsigned i,bit,m,cases=0;
 for(m=0;m<2;m++){memset(Values,0,sizeof(Values));Values[1]=m?0x80:0;Enable=0x7fc0007f;Reads=0;assert(Guard(&io,&r,out)&&Reads==11);cases++;
  for(bit=0;bit<32;bit++)if(bit!=7){Values[1]=(m?0x80:0)|(1u<<bit);assert(!Guard(&io,&r,out));cases++;}Values[1]=m?0x80:0;
  Enable|=0x80;assert(!Guard(&io,&r,out));cases++;
 }
 for(i=0;i<10;i++)for(bit=0;bit<32;bit++){memset(Values,0,sizeof(Values));Values[i]=1u<<bit;Enable=0x7fc0007f;assert(Guard(&io,&r,out)==!(Values[i]&Masks[i]));cases++;}
 memset(Values,0,sizeof(Values));Values[1]=0x80;Enable=0x33c0007e;assert(Guard(&io,&r,out));cases++;
 printf("{\\"passed\\":true,\\"cases\\":%u}\\n",cases);return 0;}
'''
f=a.output/'guard.c';f.write_text(source);exe=a.output/'guard';q=subprocess.run(['clang','-std=c11','-O1','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I',str(W),str(f),'-o',str(exe.resolve())],capture_output=True,text=True);assert not q.returncode,q.stderr
q=subprocess.run([str(exe.resolve())],capture_output=True,text=True);assert not q.returncode and not q.stderr,(q.returncode,q.stdout,q.stderr);report=json.loads(q.stdout)
report.update(actual_engine_guard_executed_unchanged=True,source_macro='M_RX_IRQ_EN BIT(7)',pinned_header_sha256=sha(h),engine_sha256=sha(W/'g50_engine.c'),native_G44_state_sha256=sha(native),G44_status80_persists_after_one_ACK_observed=True,no_extra_ACK_or_raw_status_clear_claimed=True,ASan_UBSan=True,native_commands_submitted=0,limits=['This binds the source bit definition and guard logic; the physical origin of persistent M80 is not established.','Only masked M80/0 with both sequencers idle and empty FIFOs is accepted; enabled bit7 or other master flags fail.'])
(a.output/'tests.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
