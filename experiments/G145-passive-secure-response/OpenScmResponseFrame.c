/* SPDX-License-Identifier: MIT
 * Fixed 64-byte stack observation for SCM SHA-256
 * 847b3a4cf2a8e46956a081e95d2303a65f47568094c72005db907b544f5a56ab.
 * No SMC, device operation, stack write, allocation or native integration.
 */
#include "OpenScmResponseFrame.h"
_Static_assert(sizeof(SF_U64)==8 && sizeof(SF_U32)==4,"fixed observation widths");
static unsigned Fail(SF_RESPONSE *r,unsigned fault) {
 r->Fault=fault;r->Bound=0;return fault;
}
static unsigned Range(const SF_INPUT *i,SF_U64 at,unsigned n) {
 return at>=i->StackLow && at<=i->StackHigh && n<=i->StackHigh-at;
}
static unsigned Read(const SF_INPUT *i,SF_READ read,void *context,
                     SF_RESPONSE *r,SF_U64 at,unsigned n,void *out) {
 if(!Range(i,at,n))return Fail(r,SF_BOUNDS);
 if(r->ReadAttempts>=4 || n>64-r->BytesRequested)return Fail(r,SF_BOUNDS);
 r->ReadAttempts++;r->BytesRequested+=n;
 return read(context,at,n,out)?0:Fail(r,SF_READ_FAILED);
}
unsigned OpenScmCaptureResponse(const SF_INPUT *i,SF_READ read,void *context,SF_RESPONSE *r) {
 SF_U64 formatter[2]={0},method[2]={0},values[3]={0},x6=0,fp;
 if(!r)return SF_ARGUMENT;
 unsigned char *bytes=(unsigned char *)r;
 for(unsigned n=0;n<sizeof(*r);n++)bytes[n]=0;
 if(!i || !read)return Fail(r,SF_ARGUMENT);
 if(i->CodeBound!=1 || i->StackAdmitted!=1)return Fail(r,SF_IDENTITY);
 if(i->Image!=36 || (i->Command!=0x42000201u && i->Command!=0x42000202u))
  return Fail(r,SF_REQUEST);
 if(!i->ScmBase || (i->ScmBase&4095) || i->ScmBase>~0ULL-0x10000 ||
    !i->Bytes || i->Bytes>512)return Fail(r,SF_ARGUMENT);
 if(i->StackLow>=i->StackHigh || i->StackHigh-i->StackLow>0x10000 ||
    !Range(i,i->EntrySp,0x3a0))return Fail(r,SF_BOUNDS);
 if((i->EntrySp&15) || (i->EntryFp&15) ||
    i->EntrySp>~0ULL-0x3a0 || i->EntryFp!=i->EntrySp+0x300 ||
    i->Buffer!=i->EntrySp+0xf8 || i->EntryLr!=i->ScmBase+0x70b4)
  return Fail(r,SF_CALLSITE);
 if(!(i->PrintedStatus32&0x80000000u) || (SF_U32)i->EntryX24!=i->PrintedStatus32)
  return Fail(r,SF_STATUS);
 if(Read(i,read,context,r,i->EntryFp,16,formatter))return r->Fault;
 if(formatter[0]!=i->EntryFp+0x40 || formatter[1]!=i->ScmBase+0x3c40)
  return Fail(r,SF_CHAIN);
 fp=formatter[0];
 if(Read(i,read,context,r,fp,16,method))return r->Fault;
 if(method[0]!=fp+0x50 || method[1]!=i->ScmBase+0x4014)return Fail(r,SF_CHAIN);
 if(Read(i,read,context,r,fp-0x20,24,values) ||
    Read(i,read,context,r,fp+0x18,8,&x6))return r->Fault;
 r->X0=i->EntryX24;r->X1=values[0];r->X2=values[1];r->X3=values[2];r->X6=x6;
 r->MethodFp=fp;r->Captured=1;return 0;
}
unsigned OpenScmBindResponse(SF_RESPONSE *r,SF_U64 status,SF_U64 result0) {
 SF_U64 expected;
 if(!r)return SF_ARGUMENT;
 r->Bound=0;
 if(!r->Captured)return Fail(r,SF_ARGUMENT);
 SF_U32 low=(SF_U32)r->X0;
 if(!(low&0x80000000u))return Fail(r,SF_STATUS);
 expected=low==0xffffffffu?0x8000000000000003ULL:
          low==0xfffffffeu && (SF_U32)r->X1==0xfffffff3u?0x8000000000000014ULL:
          0x8000000000000007ULL;
 if(status!=expected || result0!=r->X1)return Fail(r,SF_API_MISMATCH);
 r->Fault=0;r->Bound=1;return 0;
}
