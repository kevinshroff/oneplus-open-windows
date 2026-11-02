/* SPDX-License-Identifier: MIT -- modeled bus/PMIC, actual portable cores. */
#include "g93_power.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static const uint32_t A[17]={0x17a20000,0x17a20004,0x17a2000c,0x17a20d00,0x17a20d04,0x17a20d28,0x17a20d24,0x17a20d2c,0x17a20d34,0x17a20d38,0x17a20d3c,0x17a20d40,0x17a20d44,0x17100104,0x17100204,0x17100304,0x17100c08};
static const uint32_t B[17]={0x30000,0x4010100,0x800c8104,1,0,1,0,0,0x10108,0x50008,0x60000001,0,0,0,0,0,0};
static const uint32_t PA[8]={0xf10a000,0xf10a004,0xf118000,0xf118004,0xf119000,0xf119004,0xf119008,0xf11900c},PV[8]={1,0,0x201,0,1,0,0xe2,0};
static const uint32_t APID[3]={117,145,695},Route[3]={0x1010100,0x101c100,0x1c400},Owner[3]={4,4,0};
typedef struct {
 uint32_t Reg[17],Obs[3],Raw,InitialRaw,Voltage,Mode,SupplyModes[2],SupplyData[2];
 unsigned Reads,Writes,WaitMs,WaitUs,WaitTen,PhysicalOn,TargetOn,SupplyWrites,ObsWrites,Delay,Pending,Hit,Foreign;
 int Rfail,Wfail,Scenario;uint32_t ForceStatus,ForcedStatus;G93_POWER_RESULT*Result;
}Model;
typedef struct {unsigned Reads,Writes,Code,Restored,SupplyWrites,Raw,Txns;}Summary;
static unsigned Cases;
static void Complete(Model*m)
{
 m->Reg[4]=m->Reg[5]=1;m->Reg[11]=m->Reg[8]==0x10008?0x101:0x10101;m->Reg[6]=0x10000;
 if(m->ForceStatus)m->Reg[11]=m->ForcedStatus;
 if(m->Reg[8]==0x108){m->Reg[12]=m->Reg[9]==0x40800?m->Voltage:m->Reg[9]==0x40808?m->Mode:m->Raw;return;}
 assert((m->Reg[8]==0x10108||m->Reg[8]==0x10008)&&m->Reg[9]==0x40804&&m->Reg[10]<=1&&m->SupplyWrites<2);
 unsigned index=m->SupplyWrites++;m->SupplyModes[index]=m->Reg[8];m->SupplyData[index]=m->Reg[10];
 if(m->Reg[10]){
  assert(m->Reg[8]==0x10108);m->Raw=m->Scenario==8?0:m->Scenario==6?0x40000001u:0x80000001u;m->TargetOn=m->Scenario==8?0:1;
 }else{
  assert(m->Reg[8]==0x10008||m->Reg[8]==0x10108);if(m->Scenario!=7)m->Raw=m->Reg[8]==0x10108?0x80000000u:0;m->TargetOn=0;
 }
 if(m->Scenario==19&&m->Reg[8]==0x10008)m->Reg[11]=0x100;

}
static int Read(void*context,uint32_t at,uint32_t*value)
{
 Model*m=context;if(m->Scenario==23&&m->Result->ReleaseStarted)m->Voltage=1799;if(m->Scenario==24&&m->Result->ReleaseStarted)m->Raw=0x40000000u;if((int)++m->Reads==m->Rfail){m->Hit++;return 0;}
 assert(at!=0xc7b7000&&at!=0xc7b7008&&at!=0xb000000);
 for(unsigned i=0;i<17;i++)if(at==A[i]){
  if(i==4&&m->Pending&&m->Scenario!=14){if(!--m->Pending)Complete(m);}
  if(i==9&&m->Scenario==2&&!m->Foreign&&m->Result->TxnCount&&m->Result->Transactions[m->Result->TxnCount-1].Stage==90){m->Reg[9]=0xdeadbeef;m->Foreign=1;}
  *value=m->Reg[i];return 1;
 }
 for(unsigned i=0;i<8;i++)if(at==PA[i]){*value=PV[i];if(i==0&&(m->Scenario==3||(m->Scenario==21&&m->Result->ReleaseStarted)||(m->Scenario==22&&m->Result->PmicCount==2&&!m->Result->ReleaseStarted)))*value^=1;return 1;}
 if(at==0xc400000){*value=0x70000001;return 1;}if(at==0xc400004){*value=0x80040300;return 1;}
 for(unsigned i=0;i<3;i++){
  uint32_t base=0xc440000+APID[i]*0x20;
  if(at==0xc402000+APID[i]*4){*value=Route[i]^(m->Scenario==12?0x100:0);return 1;}
  if(at==0xc42d000+APID[i]*4){*value=Owner[i];return 1;}
  if(at==base){*value=m->Obs[i];return 1;}
  if(at==base+8){*value=m->Scenario==13&&m->ObsWrites?0:1;return 1;}
  if(at==base+0x18||at==base+0x1c){
   static const uint8_t identities[3][8]={{32,0,0,2,81,73,1,0},{0,4,1,1,4,172,0,0},{0,4,1,1,4,171,0,0}};
   static const uint8_t config[8]={8,7,0,0,7,7,0,0},active[8]={8,7,8,7,7,7,128,0};const uint8_t*p=identities[i];
   if(i==2&&m->Obs[i]==0x08000080){
    *value=m->PhysicalOn?0x87:(m->SupplyWrites?0x43:3);
    if((m->Scenario==9&&m->Result->PmicCount==1)||(m->Scenario==10&&m->Result->PmicCount==2)||(m->Scenario==11&&m->Result->PmicCount==3))*value=2;
    return 1;
   }
   if(i==2&&m->Obs[i]==0x08000407)p=m->PhysicalOn?active:config;
   *value=0;for(unsigned j=0;j<4;j++)*value|=(uint32_t)p[(at==base+0x1c?4u:0)+j]<<(8*j);return 1;
  }
 }
 fprintf(stderr,"unexpected read%x\n",at);abort();
}
static int Write(void*context,uint32_t at,uint32_t value)
{
 Model*m=context;m->Writes++;if(m->Wfail==-(int)m->Writes){m->Hit++;return 0;}
 int ok=m->Wfail!=(int)m->Writes;if(!ok)m->Hit++;
 for(unsigned i=0;i<3;i++)if(at==0xc440000+APID[i]*0x20){assert(value==0x08000007||value==0x08000080||value==0x08000407);m->Obs[i]=value;m->ObsWrites++;return ok;}
 assert(G93RscWriteAllowed(at,value));
 if(at==0x17a20d08){assert(value==1);m->Reg[4]=m->Reg[11]=0;return ok;}
 for(unsigned i=0;i<17;i++)if(at==A[i]){
  if(i>=8&&i<=10&&value==B[i])assert(!m->Reg[7]&&!m->Reg[6]&&m->Reg[5]==1);
  if(m->Foreign&&i==9)abort();
  m->Reg[i]=value;
  if(i==6&&value==0x1010000){assert(m->Reg[7]==1);m->Reg[5]=0;m->Pending=m->Delay+1;if(!m->Delay&&m->Scenario!=14){m->Pending=0;Complete(m);}}
  return ok;
 }
 abort();
}
static void WaitMs(void*context){((Model*)context)->WaitMs++;}
static void WaitUs(void*context){((Model*)context)->WaitUs++;}
static void WaitTen(void*context){Model*m=context;m->WaitTen++;m->PhysicalOn=m->TargetOn;}
static void Initialize(Model*m,G93_POWER_RESULT*r,unsigned delay,int scenario)
{
 memset(m,0,sizeof(*m));memset(r,0,sizeof(*r));m->Result=r;m->Delay=delay;m->Scenario=scenario;m->Voltage=1800;m->Mode=7;memcpy(m->Reg,B,sizeof(B));for(unsigned i=0;i<3;i++)m->Obs[i]=0x08000007;
 if(scenario==1)m->Reg[12]=7;if(scenario==4)m->Raw=0x80000000;if(scenario==5)m->Raw=1;if(scenario==16)m->Voltage=1799;if(scenario==17)m->Mode=6;if(scenario==18)m->Reg[12]=1800;m->InitialRaw=m->Raw;
}
static void Limits(Model*m,G93_POWER_RESULT*r)
{
 assert(r->TxnCount<=12&&r->PmicCount<=3&&m->SupplyWrites<=2&&m->WaitMs<=12*23&&m->WaitUs<=3*5*11&&m->WaitTen<=2&&r->Waits1ms==m->WaitMs&&r->Waits10ms==m->WaitTen);
 if(m->SupplyWrites)assert(m->SupplyModes[0]==0x10108&&m->SupplyData[0]==1);
 if(m->SupplyWrites==2)assert(m->SupplyModes[1]==0x10008&&m->SupplyData[1]==0);
 for(unsigned i=0;i<r->TxnCount;i++){
  G93_RSC_RESULT*t=r->Transactions+i;assert(t->TraceCount<=256&&t->Writes<=14&&t->Reads<=192);
  if(t->RequestData)assert(t->RequestData==1&&t->MsgId==0x10108&&t->RequestAddress==0x40804&&r->PreflightVerified);
 }
 if(r->Restored){
  assert(!r->RscUncertain&&!r->ObserverUncertain&&!r->RestoreError&&r->OffVerified&&!r->Active&&!r->NeedsRelease&&m->Raw==m->InitialRaw&&!m->PhysicalOn);
  for(unsigned i=0;i<17;i++)assert(m->Reg[i]==(i==12?(m->Scenario==1?7u:0u):B[i]));
  if(r->EnableAttempted)assert(r->LastOffObserveTxn>=r->EnableTxn&&r->LastOffObserveTxn>=r->ReleaseTxn);
 }
}
static Summary Run(int readFail,int writeFail,unsigned delay,int scenario,const char*fixture)
{
 Model m;G93_POWER_RESULT*r=calloc(1,sizeof(*r));assert(r);Initialize(&m,r,delay,scenario);m.Rfail=readFail;m.Wfail=writeFail;
 G93_POWER_IO io={{&m,Read,Write,WaitMs},{&m,Read,Write,WaitUs},WaitTen};G93PowerTrial(&io,r);Limits(&m,r);
 if(readFail||writeFail){assert(m.Hit==1);assert(r->Code||r->RestoreError||!r->Restored);}
 else if((scenario==0||scenario==1)&&delay<24){
  assert(!r->Code&&!r->RestoreError&&r->Restored&&!r->Stage&&r->PmicCount==3&&r->TxnCount==12&&r->PreflightVerified&&r->OnVerified&&r->AcquireFinished&&r->ReleaseStarted&&r->EnableAttempted&&r->ReleaseAttempted&&m.SupplyWrites==2&&m.WaitTen==2);
  assert(r->PmicKinds[0]==0&&r->PmicKinds[1]==1&&r->PmicKinds[2]==2&&r->Pmic[0].Status==3&&r->Pmic[1].Status==0x87&&r->Pmic[2].Status==0x43&&r->ClientOn==0x80000001u&&r->ClientAfter[2]==0);
 }
 else{assert(r->Code||r->RestoreError||!r->Restored);}
 if(scenario==3||scenario==4||scenario==5||scenario==9||scenario==12||scenario==13||scenario==16||scenario==17||scenario==18)assert(!m.SupplyWrites);
 if(scenario==6||scenario==21||scenario==23||scenario==24){assert(m.SupplyWrites==1&&!r->ReleaseAttempted&&!r->Restored);}
 if(scenario==8){assert(r->Code==4&&r->Restored&&m.SupplyWrites==1&&!r->ReleaseAttempted);}
 if(scenario==7){assert(!r->Restored&&m.SupplyWrites==2&&m.Raw==0x80000001u);}
 if(scenario==19||scenario==22){assert(r->Code&&r->Restored&&m.SupplyWrites==2&&!m.Raw);}
 if(scenario==2)assert(m.Foreign&&r->RscUncertain&&!r->Restored&&m.Reg[9]==0xdeadbeef);
 unsigned reads=m.Reads,writes=m.Writes;G93_POWER_RESULT*sealed=malloc(sizeof(*sealed));assert(sealed);memcpy(sealed,r,sizeof(*sealed));G93PowerTrial(&io,r);assert(m.Reads==reads&&m.Writes==writes&&!memcmp(sealed,r,sizeof(*sealed)));free(sealed);Cases++;
 if(fixture){FILE*f=fopen(fixture,"wbx");assert(f&&fwrite(r,1,sizeof(*r),f)==sizeof(*r)&&!fclose(f));}
 Summary summary={m.Reads,m.Writes,r->Code,r->Restored,m.SupplyWrites,m.Raw,r->TxnCount};free(r);Cases++;return summary;
}
int main(int argc,char**argv)
{
 assert(argc==2);Summary baseline=Run(0,0,0,0,argv[1]);Run(0,0,0,1,NULL);
 for(unsigned i=1;i<=baseline.Reads;i++)Run((int)i,0,0,0,NULL);
 for(unsigned i=1;i<=baseline.Writes;i++){Run(0,(int)i,0,0,NULL);Run(0,-(int)i,0,0,NULL);}
 for(unsigned i=0;i<=24;i++)Run(0,0,i,0,NULL);
 for(int scenario=2;scenario<=24;scenario++){if(scenario==15||scenario==20)continue;Run(0,0,0,scenario,NULL);}
 /* Prove lease handoff, duplicate refusal without hardware or poisoning the
  * result, one exact release, and stable sealed evidence after release. */
 Model m;G93_POWER_RESULT*r=calloc(1,sizeof(*r));assert(r);Initialize(&m,r,0,0);G93_POWER_IO io={{&m,Read,Write,WaitMs},{&m,Read,Write,WaitUs},WaitTen};
 assert(G93SupplyAcquire(&io,r)&&r->Active&&r->NeedsRelease&&r->OnVerified&&!r->Restored&&m.PhysicalOn&&m.Raw==0x80000001u);Cases++;
 unsigned reads=m.Reads,writes=m.Writes;G93_POWER_RESULT*sealed=malloc(sizeof(*sealed));assert(sealed);memcpy(sealed,r,sizeof(*sealed));assert(!G93SupplyAcquire(&io,r)&&!r->Code&&m.Reads==reads&&m.Writes==writes&&r->Active&&!memcmp(sealed,r,sizeof(*sealed)));Cases++;
 G93PowerTrial(&io,r);assert(m.Reads==reads&&m.Writes==writes&&!memcmp(sealed,r,sizeof(*sealed)));Cases++;
 assert(G93SupplyRelease(&io,r)&&!r->Code&&!r->Active&&!r->NeedsRelease&&!m.PhysicalOn&&!m.Raw);Limits(&m,r);Cases++;
 reads=m.Reads;writes=m.Writes;memcpy(sealed,r,sizeof(*sealed));assert(!G93SupplyRelease(&io,r)&&m.Reads==reads&&m.Writes==writes&&!memcmp(sealed,r,sizeof(*sealed)));Cases++;free(sealed);free(r);
 /* Each transport type executes the actual source on independent status data. */
 const uint32_t states[8]={0,1,0x100,0x101,0x10000,0x10001,0x10100,0x10101};
 for(int mode=0;mode<4;mode++)for(unsigned i=0;i<8;i++){
  G93_POWER_RESULT dummy;Initialize(&m,&dummy,0,0);m.ForceStatus=1;m.ForcedStatus=states[i];G93_RSC_RESULT t;memset(&t,0,sizeof(t));G93_RSC_IO transport={&m,Read,Write,WaitMs};G93Transfer(&transport,&t,mode==0?0x40800:0x40804,mode==3?1:0,mode);
  int ready=mode==2?states[i]==0x101:(states[i]&0x10100)==0x10100;assert(t.Restored==1&&t.Code==(ready?0u:8u)&&t.Completion==(ready?states[i]:0)&&m.WaitMs==(ready?0u:23u));Cases++;
 }
 for(int mode=-1;mode<=4;mode++)for(unsigned at=0;at<4;at++)for(unsigned data=0;data<3;data++){
  if(mode>=0&&mode<=3&&data==(mode==3?1u:0u)&&((mode==0&&at<3)||(mode>0&&at==1)))continue;
  G93_POWER_RESULT dummy;Initialize(&m,&dummy,0,0);G93_RSC_RESULT t;memset(&t,0,sizeof(t));G93_RSC_IO transport={&m,Read,Write,WaitMs};const uint32_t address[4]={0x40800,0x40804,0x40808,0x4080c};G93Transfer(&transport,&t,address[at],data,mode);assert(t.Code==1&&!m.Reads&&!m.Writes);Cases++;
 }
 printf("{\"passed\":true,\"cases\":%u,\"normal_reads\":%u,\"normal_register_writes\":%u,\"normal_transactions\":%u,\"maximum_resource_writes\":2,\"native_operations\":0,\"result_bytes\":%zu}\n",Cases,baseline.Reads,baseline.Writes,baseline.Txns,sizeof(G93_POWER_RESULT));return 0;
}
