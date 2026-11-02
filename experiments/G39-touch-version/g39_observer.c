/* SPDX-License-Identifier: MIT
 * Fixed port of the G30 native-qualified observer READ sequence.
 * No direct SPMI RW channel or PMIC configuration command is supported.
 */
#include "g39_observer.h"
typedef struct {uint32_t Apid, Map, Owner; const uint8_t *Identity;} G39_TARGET;
static const uint8_t Revision[8]={32,0,0,2,81,73,1,0};
static const uint8_t Anchor[8]={0,4,1,1,4,172,0,0};
static const uint8_t Identity[8]={0,4,1,1,4,171,0,0};
static const G39_TARGET Targets[3]={
 {117,0x1010100,4,Revision},{145,0x101c100,4,Anchor},{695,0x1c400,0,Identity}
};
static int Event(G39_OBS_RESULT *r,uint32_t kind,uint32_t address,uint32_t value)
{
 G39_OBS_EVENT *e;
 if(r->TraceCount>=G39_TRACE_LIMIT){r->Code=G39_OBS_BUDGET;return 0;}
 e=&r->Trace[r->TraceCount++];e->Kind=kind;e->Address=address;e->Value=value;
 return 1;
}
static int Read(const G39_OBS_IO *io,G39_OBS_RESULT *r,uint32_t at,uint32_t *value)
{
 if(r->Reads>=120){r->Code=G39_OBS_BUDGET;return 0;}
 r->Reads++;
 if(!io->Read(io->Context,at,value)){r->Code=G39_OBS_IO_ERROR;Event(r,3,at,0);return 0;}
 return Event(r,1,at,*value);
}
static int Write(const G39_OBS_IO *io,G39_OBS_RESULT *r,uint32_t at,uint32_t value)
{
 if(r->Writes>=5||!((at==0xc440ea0||at==0xc441220||at==0xc4456e0)&&
   (value==0x08000007||value==0x08000080||value==0x08000407))){r->Code=G39_OBS_BUDGET;return 0;}
 r->Writes++;
 if(!Event(r,2,at,value))return 0;
 if(!io->Write(io->Context,at,value)){r->Code=G39_OBS_IO_ERROR;return 0;}
 return 1;
}
static int ReadTarget(const G39_OBS_IO *io,G39_OBS_RESULT *r,unsigned target,
 unsigned offset,unsigned length,uint8_t *out,unsigned index)
{
 const G39_TARGET *t=&Targets[target];uint32_t map,owner,status,previous,data0,data1=0;
 uint32_t base=0xc440000+t->Apid*0x20,command;unsigned i;
 r->Stage=10+index;
 if(!Read(io,r,0xc402000+t->Apid*4,&map)||!Read(io,r,0xc42d000+t->Apid*4,&owner))return 0;
 if(map!=t->Map||owner!=t->Owner){r->Code=G39_OBS_ROUTE;return 0;}
 r->Stage=20+index;
 if(!Read(io,r,base+8,&status)||!Read(io,r,base,&previous))return 0;
 if(!(status&1)&&previous){r->Code=G39_OBS_PENDING;return 0;}
 command=0x08000000u|(offset<<4)|(length-1);
 r->Stage=30+index;r->Commands++;
 if(!Write(io,r,base,command))return 0;
 r->Stage=40+index;
 for(i=0;i<12;i++){
  r->Polls++;
  if(!Read(io,r,base+8,&status))return 0;
  if(status&1)break;
  if(i+1<12)io->WaitMicrosecond(io->Context);
 }
 r->Completion[index]=status;
 if(!(status&1)){r->Code=G39_OBS_TIMEOUT;return 0;}
 r->Stage=50+index;
 if(status&0xe){r->Code=G39_OBS_COMPLETION_ERROR;return 0;}
 if(!Read(io,r,base+0x18,&data0))return 0;
 if(length>4&&!Read(io,r,base+0x1c,&data1))return 0;
 for(i=0;i<length;i++)out[i]=(uint8_t)((i<4?data0:data1)>>((i%4)*8));
 return 1;
}
void G39Observe(const G39_OBS_IO *io,G39_OBS_RESULT *r)
{
 uint32_t version,features;unsigned target,i;uint8_t *outputs[3];
 outputs[0]=r->Revision;outputs[1]=r->Anchor;outputs[2]=r->Identity;
 r->Stage=1;
 if(!Read(io,r,0xc400000,&version)||!Read(io,r,0xc400004,&features))return;
 if(version!=0x70000001||features!=0x80040300){r->Code=G39_OBS_ARBITER;return;}
 for(target=0;target<3;target++){
  if(!ReadTarget(io,r,target,0,8,outputs[target],target))return;
  r->Stage=60+target;
  for(i=0;i<8;i++)if(outputs[target][i]!=Targets[target].Identity[i]){r->Code=G39_OBS_IDENTITY;return;}
 }
 if(!ReadTarget(io,r,2,8,1,&r->Status,3)||!ReadTarget(io,r,2,0x40,8,r->Configuration,4))return;
 r->Stage=0;r->Code=G39_OBS_OK;
}
