/* SPDX-License-Identifier: MIT */
#include "g38_power.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static const uint32_t Ra[17]={0x17a20000,0x17a20004,0x17a2000c,0x17a20d00,0x17a20d04,0x17a20d28,0x17a20d24,0x17a20d2c,0x17a20d34,0x17a20d38,0x17a20d3c,0x17a20d40,0x17a20d44,0x17100104,0x17100204,0x17100304,0x17100c08};
static const uint32_t Rb[17]={0x30000,0x4010100,0x800c8104,1,0,1,0,0,0x10108,0x50008,0x60000001,0,7,0,0,0,0};
static const uint32_t Pa[8]={0xf10a000,0xf10a004,0xf118000,0xf118004,0xf119000,0xf119004,0xf119008,0xf11900c},Pv[8]={1,0,0x201,0,1,0,0xe2,0};
typedef struct {uint32_t Reg[17],ObsCmd[3];int Rfail,Wfail,Scenario,Delay,Pending,Enabled,Enables,Releases,Reads,Writes,OwnerUsed;G38_RSC_RESULT*Single;G38_POWER_RESULT*Power;} Model;
static G38_RSC_RESULT*Current(Model*m){return m->Power&&m->Power->TxnCount?&m->Power->Transactions[m->Power->TxnCount-1]:m->Single;}
static void Complete(Model*m)
{
 m->Reg[4]=1;m->Reg[5]=1;m->Reg[11]=0x10101;m->Reg[6]=0x10000;
 if(m->Reg[8]==0x10108&&m->Reg[9]==0x40804){m->Enabled=(int)m->Reg[10];if(m->Enabled)m->Enables++;else m->Releases++;}
 if(m->Reg[8]==0x108){m->Reg[12]=m->Reg[9]==0x40800?1800:m->Reg[9]==0x40808?7:0x80000000u|(uint32_t)m->Enabled;}
}
static int Read(void*context,uint32_t at,uint32_t*out)
{
 Model*m=context;G38_RSC_RESULT*x=Current(m);unsigned i;m->Reads++;if(m->Reads==m->Rfail)return 0;
 for(i=0;i<17;i++)if(at==Ra[i]){
  if(i==4&&m->Pending>0&&m->Scenario!=1&&!(m->Scenario==6&&m->Reg[8]==0x10108&&m->Reg[10]==1)){if(--m->Pending==0)Complete(m);}
  if(x&&x->Stage==90&&(m->Scenario==2||(m->Scenario==7&&m->Enabled))&&!m->OwnerUsed&&i==9){m->Reg[9]=0xdeadbeef;m->OwnerUsed=1;}
  *out=m->Reg[i];return 1;
 }
 for(i=0;i<8;i++)if(at==Pa[i]){*out=Pv[i];if(m->Scenario==20+(int)i)*out^=1;return 1;}
 if(at==0xc400000){*out=0x70000001;return 1;}if(at==0xc400004){*out=0x80040300;return 1;}
 {const uint32_t apid[3]={117,145,695},maps[3]={0x1010100,0x101c100,0x1c400},owner[3]={4,4,0};
 for(i=0;i<3;i++){
  uint32_t base=0xc440000+apid[i]*0x20;
  if(at==0xc402000+apid[i]*4){*out=maps[i];return 1;}if(at==0xc42d000+apid[i]*4){*out=owner[i];return 1;}
  if(at==base){*out=m->ObsCmd[i];return 1;}if(at==base+8){*out=1;return 1;}
  if(at==base+0x18||at==base+0x1c){
   static const uint8_t ids[3][8]={{32,0,0,2,81,73,1,0},{0,4,1,1,4,172,0,0},{0,4,1,1,4,171,0,0}};
   static const uint8_t cfg[2][8]={{8,7,0,0,7,7,0,0},{8,7,8,7,7,7,128,0}};
   const uint8_t*bytes=ids[i];unsigned j,offset=at==base+0x1c?4u:0u;
   if(i==2&&m->ObsCmd[i]==0x08000080){*out=m->Enabled?0xc7u:0x43u;if(m->Scenario==3&&m->Enabled)*out^=0x20;if(m->Scenario==4&&!m->Enabled&&m->Enables)*out=3;return 1;}
   if(i==2&&m->ObsCmd[i]==0x08000407)bytes=cfg[m->Enabled];
   *out=0;for(j=0;j<4;j++)*out|=(uint32_t)bytes[offset+j]<<(j*8);
   if(m->Scenario==5&&m->Enabled&&i==2&&m->ObsCmd[i]==0x08000407)*out^=1;
   return 1;
  }
 }}
 fprintf(stderr,"unexpected read%x\n",at);exit(20);
}
static int Write(void*context,uint32_t at,uint32_t value)
{
 Model*m=context;unsigned i;m->Writes++;if(m->Wfail==-m->Writes)return 0;
 if(at==0xc440ea0||at==0xc441220||at==0xc4456e0){i=at==0xc440ea0?0:at==0xc441220?1:2;m->ObsCmd[i]=value;return m->Wfail!=m->Writes;}
 if(!G38RscWriteAllowed(at,value)){fprintf(stderr,"unexpected write%x/%x\n",at,value);exit(21);}
 if(at==0x17a20d08){m->Reg[4]=0;m->Reg[11]=0;return m->Wfail!=m->Writes;}
 for(i=0;i<17;i++)if(at==Ra[i]){
  if(i>=8&&i<=10&&value==Rb[i]&&(m->Reg[7]||m->Reg[6]||m->Reg[5]!=1)){fputs("old WRITE payload restored without exclusion\n",stderr);exit(22);}
  m->Reg[i]=value;
  if(i==6&&value==0x1010000){
   if(m->Reg[7]!=1)exit(23);m->Pending=m->Delay+1;m->Reg[5]=0;
   if(m->Delay==0&&m->Scenario!=1&&!(m->Scenario==6&&m->Reg[8]==0x10108&&m->Reg[10]==1)){m->Pending=0;Complete(m);}
  }
  return m->Wfail!=m->Writes;
 }
 exit(24);
}
static void Wait1(void*context){Model*m=context;if(m->Power)m->Power->Waits1ms++;}
static void Wait10(void*context){(void)context;}
static void WaitUs(void*context){(void)context;}
int main(int argc,char**argv)
{
 Model m;G38_RSC_RESULT x;G38_POWER_RESULT p;G38_POWER_IO io;unsigned i,j;int restored,mode;
 if(argc!=6)return 2;memset(&m,0,sizeof(m));memset(&x,0,sizeof(x));memset(&p,0,sizeof(p));
 mode=atoi(argv[1]);m.Rfail=atoi(argv[2]);m.Wfail=atoi(argv[3]);m.Scenario=atoi(argv[4]);m.Delay=atoi(argv[5]);memcpy(m.Reg,Rb,sizeof(Rb));m.Single=&x;if(mode==2)m.Power=&p;
 for(i=0;i<3;i++)m.ObsCmd[i]=0x08000007;
 io.Rsc.Context=&m;io.Rsc.Read=Read;io.Rsc.Write=Write;io.Rsc.WaitMillisecond=Wait1;io.Observer.Context=&m;io.Observer.Read=Read;io.Observer.Write=Write;io.Observer.WaitMicrosecond=WaitUs;io.WaitTenMilliseconds=Wait10;
 if(mode==2)G38PowerTrial(&io,&p);else G38Transfer(&io.Rsc,&x,0x40804,mode==1?1:0,mode==1);
 restored=!m.Enabled;for(i=0;i<11;i++)restored=restored&&m.Reg[i]==Rb[i];
 printf("{\"code\":%u,\"restore_error\":%u,\"restored\":%u,\"physical_model_restored\":%d,\"on_verified\":%u,\"off_verified\":%u,\"rsc_uncertain\":%u,\"observer_uncertain\":%u,\"reads\":%d,\"writes\":%d,\"enabled\":%d,\"enables\":%d,\"releases\":%d,\"transactions\":%u,\"RSC_writes\":[",mode==2?p.Code:x.Code,mode==2?p.RestoreError:x.RestoreError,mode==2?p.Restored:x.Restored,restored,p.OnVerified,p.OffVerified,p.RscUncertain,p.ObserverUncertain,m.Reads,m.Writes,m.Enabled,m.Enables,m.Releases,mode==2?p.TxnCount:1);
 {unsigned count=0,n=mode==2?p.TxnCount:1;for(i=0;i<n;i++){G38_RSC_RESULT*t=mode==2?&p.Transactions[i]:&x;for(j=0;j<t->TraceCount;j++)if(t->Trace[j].Kind==2)printf("%s[%u,%u]",count++?",":"",t->Trace[j].Address,t->Trace[j].Value);}}
 puts("]}");return 0;
}
