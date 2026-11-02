/* SPDX-License-Identifier: MIT */
#include "OpenScmErrorCapture.h"
_Static_assert(sizeof(void *)==8&&sizeof(OL_U64)==8&&sizeof(OL_U32)==4,"64-bit capture ABI");
_Static_assert(sizeof(OL_RECORD)==32&&sizeof(OL_REPORT)==272,"fixed report ABI");
static void Inc(OL_U32 *n){if(*n!=0xffffffffu)(*n)++;}
static void Refuse(OL_STATE *s,OL_U32 reason){Inc(&s->Report.Rejected);s->Report.ParserFault|=reason;}
void OpenScmLogInit(OL_STATE *s)
{
 if(!s)return;
 unsigned char *p=(unsigned char *)s;
 for(unsigned long i=0;i<sizeof(*s);i++)p[i]=0;
 s->Report.Size=sizeof(s->Report);s->Report.Version=1;s->Report.Magic=OL_MAGIC;
 s->Report.HookStatus=s->Report.RestoreStatus=0x8000000000000006ULL;
}
unsigned OpenScmLogBegin(OL_STATE *s,OL_U32 command,OL_U64 image,
                        OL_U32 sequence,OL_U64 anchor)
{
 if(!s||!s->Report.Active)return 0;
 if(image!=36||(command!=0x42000201u&&command!=0x42000202u))return 0;
 if(s->Report.PendingCommand||sequence>=16){Refuse(s,OL_BAD_STATE);return 0;}
 if(anchor<OL_MIN_STACK_ANCHOR||anchor>~0ULL-OL_STACK_ABOVE){Refuse(s,OL_BAD_STACK);return 0;}
 s->Report.StackLow=anchor-OL_STACK_BELOW;s->Report.StackHigh=anchor+OL_STACK_ABOVE;
 s->Report.PendingCommand=command;s->PendingSequence=sequence;s->BeginCount=s->Report.Count;
 return 1;
}
void OpenScmLogEnd(OL_STATE *s,OL_U64 status,OL_U64 result0)
{
 if(!s||!s->Report.PendingCommand)return;
 for(OL_U32 i=s->BeginCount;i<s->Report.Count&&i<OL_RECORDS;i++){
  s->Report.Records[i].ApiStatus=status;s->Report.Records[i].ApiResult0=result0;
 }
 s->Report.PendingCommand=0;s->BeginCount=s->Report.Count;s->PendingSequence=0;
}
static unsigned Literal(const unsigned char *b,OL_U64 n,OL_U64 *at,const char *want)
{
 while(*want){if(*at>=n||b[*at]!=(unsigned char)*want)return 0;(*at)++;want++;}
 return 1;
}
static unsigned Hex(const unsigned char *b,OL_U64 n,OL_U64 *at,OL_U32 *out)
{
 unsigned digits=0;OL_U32 value=0;
 while(*at<n){unsigned c=b[*at],v;
  if(c>='0'&&c<='9')v=c-'0';
  else if(c>='a'&&c<='f')v=c-'a'+10;
  else if(c>='A'&&c<='F')v=c-'A'+10;
  else break;
  if(digits==8)return 0;digits++;value=(value<<4)|v;(*at)++;
 }
 if(!digits)return 0;*out=value;return 1;
}
OL_U64 OpenScmLogConsume(OL_STATE *s,const void *buffer,OL_U64 n)
{
 OL_U64 address=(OL_U64)buffer,at=0;OL_U32 raw,command;
 const unsigned char *b=buffer;
 if(!s)return 0;
 Inc(&s->Report.SinkCalls);
 if(!s->Report.Active||!s->Report.PendingCommand){Inc(&s->Report.Ignored);return 0;}
 if(!buffer||!n||n>512){Refuse(s,OL_BAD_LENGTH);return 0;}
 /* Validate the entire range before any character read. The adapter derives
  * bounds from its own live stack frame immediately around the original call.
  * This excludes serial reads of unrelated RAM or device/IMEM pointers. */
 if(address<s->Report.StackLow||address>s->Report.StackHigh||
    n>s->Report.StackHigh-address){Refuse(s,OL_BAD_STACK);return 0;}
 if(!Literal(b,n,&at,"tz_armv8_smc_call failed, TzStatus = 0x")){
  Inc(&s->Report.Ignored);return n;
 }
 if(!Hex(b,n,&at,&raw)||!Literal(b,n,&at,",  SmcId = 0x")||
    !Hex(b,n,&at,&command)||!Literal(b,n,&at,"  ")){
  Refuse(s,OL_BAD_FORMAT);return n;
 }
 unsigned newline=0,count=0;
 for(;at<n;at++){
  if((b[at]!='\r'&&b[at]!='\n')||++count>4){Refuse(s,OL_BAD_FORMAT);return n;}
  if(b[at]=='\n')newline=1;
 }
 if(!newline){Refuse(s,OL_BAD_FORMAT);return n;}
 if(command!=s->Report.PendingCommand){Refuse(s,OL_WRONG_COMMAND);return n;}
 if(s->Report.Count>=OL_RECORDS){Refuse(s,OL_CAPACITY);return n;}
 for(OL_U32 i=s->BeginCount;i<s->Report.Count;i++){
  if(s->Report.Records[i].Sequence==s->PendingSequence){Refuse(s,OL_DUPLICATE);return n;}
 }
 OL_RECORD *r=&s->Report.Records[s->Report.Count++];
 r->Command=command;r->RawStatus=raw;r->Sequence=s->PendingSequence;r->TextBytes=(OL_U32)n;
 Inc(&s->Report.Matched);return n;
}
