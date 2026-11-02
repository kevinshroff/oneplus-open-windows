#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "OpenPilCpuInventory.c"
static unsigned Kind,Cases;
static P139_U64 Calls;
static P139_U64 Query(void *context,P139_U64 address,unsigned write)
{
 P139_U64 index=Calls/2,tag=0x44,pa=address;
 assert(context==&Calls && index<P139_PAGE_COUNT);
 assert(address==P139_WINDOW_START+index*4096 && write==(Calls&1));Calls++;
 if(Kind==1 && !write && index==0)return 0xff00000000000001ULL;
 if(Kind==2 && write && index==P139_PAGE_COUNT-1)return 1;
 if(Kind==3 && index==P139_PAGE_COUNT/2)return 1;
 if(Kind==4 && !write && index==7)pa+=4096;
 if(Kind==5 && write && index==11)pa-=4096;
 if(Kind==6)tag=write?0xff:0x44;
 if(Kind==7)tag=(index+write)&255;
 if(Kind==8)tag=0;
 return (tag<<56)|pa|0xa80; /* Lower PAR metadata is not a PA alias. */
}
static void Run(unsigned kind)
{
 struct{P139_U64 before;P139_CPU_INVENTORY r;P139_U64 after;} guarded;
 P139_U64 rt=0,wt=0;memset(&guarded,0xac,sizeof guarded);
 guarded.before=0x1122334455667788ULL;guarded.after=0x8877665544332211ULL;
 Kind=kind;Calls=0;assert(OpenCollectPilCpu(&guarded.r,Query,&Calls,1)==0);
 assert(Calls==37376 && guarded.r.Pages==18688 && guarded.r.Queries==37376 && guarded.r.Complete);
 assert(guarded.before==0x1122334455667788ULL && guarded.after==0x8877665544332211ULL);
 for(unsigned i=0;i<256;i++){rt+=guarded.r.ReadTags[i];wt+=guarded.r.WriteTags[i];}
 assert(rt+guarded.r.ReadFaults==18688 && wt+guarded.r.WriteFaults==18688);
 if(kind==0)assert(guarded.r.ReadTags[0x44]==18688 && guarded.r.WriteTags[0x44]==18688 && !guarded.r.FirstFault && !guarded.r.FirstAlias && !guarded.r.TagDifferences);
 if(kind==1)assert(guarded.r.ReadFaults==1 && !guarded.r.WriteFaults && guarded.r.FirstFault==P139_WINDOW_START && guarded.r.FaultReadPar==0xff00000000000001ULL);
 if(kind==2)assert(guarded.r.WriteFaults==1 && !guarded.r.ReadFaults && guarded.r.FirstFault==P139_WINDOW_END-4096);
 if(kind==3)assert(guarded.r.ReadFaults==1 && guarded.r.WriteFaults==1 && guarded.r.FirstFault==P139_WINDOW_START+(18688/2)*4096ULL);
 if(kind==4)assert(guarded.r.ReadAliases==1 && !guarded.r.WriteAliases && guarded.r.FirstAlias==P139_WINDOW_START+7*4096);
 if(kind==5)assert(guarded.r.WriteAliases==1 && !guarded.r.ReadAliases && guarded.r.FirstAlias==P139_WINDOW_START+11*4096);
 if(kind==6)assert(guarded.r.TagDifferences==18688 && guarded.r.FirstTagDifference==P139_WINDOW_START && guarded.r.WriteTags[0xff]==18688);
 if(kind==7){for(unsigned i=0;i<256;i++)assert(guarded.r.ReadTags[i]==73 && guarded.r.WriteTags[i]==73);assert(guarded.r.TagDifferences==18688);}
 if(kind==8)assert(guarded.r.ReadTags[0]==18688 && guarded.r.WriteTags[0]==18688 && !guarded.r.TagDifferences);
 Cases++;
}
int main(void)
{
 P139_CPU_INVENTORY r;
 for(unsigned i=0;i<9;i++)Run(i);
 Calls=0;assert(OpenCollectPilCpu(NULL,Query,&Calls,1)==1 && Calls==0);Cases++;
 for(unsigned el=0;el<4;el++)if(el!=1 && el!=2){memset(&r,0xac,sizeof r);Calls=0;assert(OpenCollectPilCpu(&r,Query,&Calls,el)==1 && Calls==0 && r.El==el && !r.Complete && !r.Pages && !r.Queries);Cases++;}
 memset(&r,0xac,sizeof r);assert(OpenCollectPilCpu(&r,NULL,&Calls,1)==1 && Calls==0 && !r.Complete);Cases++;
 Kind=0;Calls=0;assert(OpenCollectPilCpu(&r,Query,&Calls,2)==0 && r.El==2 && r.Complete && Calls==37376);Cases++;
 Kind=1;Calls=0;assert(OpenCollectPilCpu(&r,Query,&Calls,1)==0 && r.ReadFaults==1);Calls=0;Kind=0;
 assert(OpenCollectPilCpu(&r,Query,&Calls,1)==0 && !r.ReadFaults && r.ReadTags[0x44]==18688);Cases++;
 printf("{\"passed\":true,\"cases\":%u,\"fixed_pages\":18688,\"queries_per_complete_collection\":37376,\"native_operations\":0}\n",Cases);
}
