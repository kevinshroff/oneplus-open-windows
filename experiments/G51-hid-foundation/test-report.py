"""Execute real report code with bit mutations; independently decode HID items."""
from pathlib import Path
import argparse,hashlib,json,subprocess
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True);W=Path(__file__).resolve().parent
c=r'''
#include "g51_report.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
int main(int argc,char**argv){uint8_t b[64],f[8];uint32_t scan,i,bit,w,cases=0;FILE*out;if(argc!=2)return 2;
 for(scan=0;scan<65536;scan++){G51EmptyReport(b,(uint16_t)scan);assert(G51IsEmptyReport(b,64)&&b[0]==1&&b[61]==(uint8_t)scan&&b[62]==(uint8_t)(scan>>8)&&b[63]==0);cases++;}
 for(i=0;i<64;i++)for(bit=0;bit<8;bit++){G51EmptyReport(b,0);b[i]^=(uint8_t)(1u<<bit);assert(G51IsEmptyReport(b,64)==(i==61||i==62));cases++;}
 for(i=0;i<128;i++)if(i!=64){assert(!G51IsEmptyReport(b,i));cases++;}assert(!G51IsEmptyReport(NULL,64));cases++;
 for(i=0;i<256;i++){memset(f,0xa5,sizeof(f));w=9;assert(G51GetFeature((uint8_t)i,f,8,&w)==(i==2));if(i==2)assert(w==2&&f[0]==2&&f[1]==10&&f[2]==0xa5);else assert(!w&&f[0]==0xa5);cases++;}
 for(i=0;i<2;i++){w=9;assert(!G51GetFeature(2,f,i,&w)&&!w);cases++;}assert(!G51GetFeature(2,NULL,2,&w)&&!w&&!G51GetFeature(2,f,2,NULL));cases++;
 out=fopen(argv[1],"wb");assert(out&&fwrite(G51Descriptor,1,G51DescriptorBytes,out)==G51DescriptorBytes);fclose(out);
 printf("{\"passed\":true,\"cases\":%u,\"descriptor_bytes\":%u,\"input_report_bytes\":64,\"maximum_contacts\":10,\"only_zero_contact_reports_generated\":true}\n",cases,G51DescriptorBytes);return 0;}
'''
f=a.output/'test-report.c';f.write_text(c);exe=a.output/'test-report';q=subprocess.run(['clang','-std=c11','-O1','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I',str(W),str(W/'g51_report.c'),str(f),'-o',str(exe.resolve())],capture_output=True,text=True);assert not q.returncode,q.stderr
q=subprocess.run([str(exe.resolve()),str((a.output/'descriptor.bin').resolve())],capture_output=True,text=True);assert not q.returncode and not q.stderr,(q.stdout,q.stderr);v=json.loads(q.stdout);data=(a.output/'descriptor.bin').read_bytes()
# Independent HID short-item interpreter. Offsets exclude the report-ID byte.
g={'page':0,'min':0,'max':0,'size':0,'count':0,'id':0};usages=[];stack=[];bits={};values=[];collections=[];i=0
while i<len(data):
 b=data[i];i+=1;assert b!=0xfe;n=[0,1,2,4][b&3];kind=(b>>2)&3;tag=b>>4;assert i+n<=len(data);raw=data[i:i+n];i+=n;value=int.from_bytes(raw,'little')
 if kind==1:
  if tag in{0,1,2,7,8,9}:g[{0:'page',1:'min',2:'max',7:'size',8:'id',9:'count'}[tag]]=value
  elif tag==10:stack.append(dict(g))
  elif tag==11:g=stack.pop()
  else:assert tag in[3,4,5,6]
 elif kind==2:
  assert tag==0;usages.append((g['page'],value))
 elif kind==0:
  if tag==10:collections.append((value,usages[-1]));usages=[]
  elif tag==12:assert collections;collections.pop();usages=[]
  elif tag in[8,11]:
   typ='input'if tag==8 else'feature';key=(typ,g['id']);at=bits.get(key,0)
   if not(value&1):
    assert len(usages)==g['count'];values.extend({'type':typ,'id':g['id'],'offset':at+k*g['size'],'size':g['size'],'usage':u,'max':g['max']}for k,u in enumerate(usages))
   bits[key]=at+g['count']*g['size'];usages=[]
  else:raise AssertionError(('main',tag))
 else:raise AssertionError(('item',kind,tag))
assert not collections and not stack and bits=={('input',1):504,('feature',2):8}
for usage,offset,size,maximum in[((13,66),0,1,1),((13,71),1,1,1),((13,81),8,8,15),((1,48),16,16,22680),((1,49),32,16,24400)]:
 rows=[x for x in values if x['type']=='input'and x['usage']==usage];assert len(rows)==10 and all(x['offset']==offset+k*48 and x['size']==size and x['max']==maximum for k,x in enumerate(rows))
assert any(x['usage']==(13,86)and x['offset']==480 and x['size']==16 for x in values)
assert any(x['usage']==(13,84)and x['offset']==496 and x['size']==8 and x['max']==10 for x in values)
assert any(x['type']=='feature'and x['id']==2 and x['usage']==(13,85)and x['size']==8 and x['max']==10 for x in values)
v.update(ASan_UBSan=True,independent_HID_item_parser_agrees_with_real_C_report_layout=True,descriptor_sha256=hashlib.sha256(data).hexdigest(),source_sha256={n:hashlib.sha256((W/n).read_bytes()).hexdigest()for n in['g51_report.c','g51_report.h']},native_operations=0,limits=['No Windows parser, device installation or physical touch is exercised here.','Physical geometry, rotation and live contact mapping remain unqualified.'])
(a.output/'tests.json').write_text(json.dumps(v,indent=2)+'\n');print(json.dumps(v))
