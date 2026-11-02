/* SPDX-License-Identifier: MIT */
#include "OpenPasObserver.h"
_Static_assert(sizeof(OP_U64)==8 && sizeof(OP_U32)==4,"fixed ABI widths");
_Static_assert(sizeof(OP_RECORD)==96,"report record ABI");
void OpenPasInit(OP_OBSERVER *o,OP_SIP fn,void *protocol,OP_U32 abi)
{
 if(!o)return;
 unsigned char *p=(unsigned char *)o;
 for(unsigned long i=0;i<sizeof(*o);i++)p[i]=0;
 o->Original=fn;o->ExpectedThis=protocol;o->ABI=abi;
}
OP_U64 OpenPasArm(OP_OBSERVER *o)
{
 if(!o||!o->Original||!o->ExpectedThis||
    (o->ABI!=OP_ABI_LEGACY && o->ABI!=OP_ABI_ARMV8))return OP_ERR(2);
 if(o->Consumed||o->Busy||o->Fault||o->Count)return OP_ERR(15);
 o->Consumed=1;o->Active=1;return 0;
}
OP_U64 OpenPasDisarm(OP_OBSERVER *o)
{
 if(!o)return OP_ERR(2);
 if(o->Busy)return OP_ERR(6);
 o->Active=0;return 0;
}
static OP_U64 Refuse(OP_OBSERVER *o,OP_RECORD *r,OP_U32 why,OP_U64 status)
{
 o->Fault|=why;r->Refusal=why;r->ReturnedStatus=status;return status;
}
OP_U64 OpenPasCall(OP_OBSERVER *o,void *self,OP_U32 command,OP_U32 param,
                  OP_U64 *args,OP_U64 *results)
{
 OP_U32 id=command&~0xc0000000u,index,stage,n;
 OP_U64 effective_image;
 OP_U64 status,base,bytes;
 OP_RECORD *r;
 if(!o||!o->Original)return OP_ERR(2);
 /* Legacy SCM packs only the low16 command bits and low32 argument bits. */
 if(o->ABI==OP_ABI_LEGACY)id=0x02000000u|(command&0xffffu);
 /* Outside the explicit window or PAS subset, preserve the existing API. */
 if(!o->Active)
  return o->Original(self,command,param,args,results);
 if(id!=0x02000201u&&id!=0x02000202u&&id!=0x02000205u&&id!=0x02000206u){
  if(o->Verify&&!o->Verify(self)){o->Fault|=OP_OWNERSHIP;return OP_ERR(15);}
  return o->Original(self,command,param,args,results);
 }
 effective_image=args?(o->ABI==OP_ABI_LEGACY?(OP_U32)args[0]:args[0]):0;
 if(o->Busy){o->Fault|=OP_REENTRANT;return OP_ERR(15);}
 if(o->Count>=OP_RECORDS){o->Fault|=OP_CAPACITY;return OP_ERR(9);}
 r=&o->Records[o->Count++];r->Command=command;r->ParamId=param;
 if(o->Fault)return Refuse(o,r,OP_ORDER,OP_ERR(15));
 if(!args||!results||self!=o->ExpectedThis||command!=(id|0x40000000u))
  return Refuse(o,r,OP_BAD_ARGUMENT,OP_ERR(2));
 r->ImageId=(OP_U32)effective_image;r->Arguments[0]=args[0];
 if(effective_image!=1&&effective_image!=36)
  return Refuse(o,r,OP_BAD_ARGUMENT,OP_ERR(2));
 if(args[0]!=effective_image)return Refuse(o,r,OP_BAD_ARGUMENT,OP_ERR(2));
 index=(effective_image==36)?0u:1u;
 if(id==0x02000206u)return Refuse(o,r,OP_SHUTDOWN,OP_ERR(15));
 stage=id==0x02000201u?0u:id==0x02000202u?1u:2u;
 if(param!=(stage==0?0x82u:stage==1?3u:1u))
  return Refuse(o,r,OP_BAD_ARGUMENT,OP_ERR(2));
 n=param&15u;for(OP_U32 i=0;i<n;i++)r->Arguments[i]=args[i];
 /* This diagnostic only enters DTB INIT and MEM_SETUP. Reject any main-image
  * or authentication request before it can reach the original SCM method. */
 if(index==1||stage==2)return Refuse(o,r,OP_DIAGNOSTIC_STOP,OP_ERR(21));
 if(o->Phase[index]!=stage || (index==1 && o->Phase[0]!=3))
  return Refuse(o,r,OP_ORDER,OP_ERR(15));
 base=index==0?0x9e980000ULL:0x9ea00000ULL;
 bytes=index==0?0x80000ULL:0x4880000ULL;
 if((stage==0 && (!args[1] || (o->ABI==OP_ABI_LEGACY && args[1]>0xffffffffULL))) ||
    (stage==1 && (args[1]!=base || args[2]!=bytes)))
  return Refuse(o,r,OP_BAD_ARGUMENT,OP_ERR(2));
 if(o->Verify&&!o->Verify(self))return Refuse(o,r,OP_OWNERSHIP,OP_ERR(15));
 r->Entered=1;o->Busy=1;
 if(stage==2)o->AuthEnteredMask|=1u<<index;
 status=o->Original(self,command,param,args,results);
 r->OriginalStatus=status;r->Returned=1;
 for(OP_U32 i=0;i<4;i++)r->Results[i]=results[i];
 o->Busy=0;
 if(o->Fault)return Refuse(o,r,OP_REENTRANT,OP_ERR(15));
 if(status)return Refuse(o,r,OP_TRANSPORT,(status>>63)?status:OP_ERR(7));
 if(results[0]!=1)return Refuse(o,r,OP_RESULT_HEADER,OP_ERR(33));
 if(results[1]!=0)return Refuse(o,r,OP_SERVICE_RESULT,OP_ERR(7));
 o->Phase[index]=stage+1;
 /* Retain real MEM_SETUP success, then stop the public PIL loader before it
  * copies a payload or performs proxy/authentication/start actions. */
 if(stage==1)return Refuse(o,r,OP_DIAGNOSTIC_STOP,OP_ERR(21));
 if(stage==2)o->AuthAcceptedMask|=1u<<index;
 r->ReturnedStatus=0;return 0;
}
