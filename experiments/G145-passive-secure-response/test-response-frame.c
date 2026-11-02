/* SPDX-License-Identifier: MIT
 * Original-code frame fixtures plus independent qualification/failure cases.
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "OpenScmResponseFrame.h"
#include "original-frames.h"

typedef struct { MODEL Model;unsigned Reads,FailRead,CorruptRead,CorruptByte; } MEMORY;
static unsigned Cases;
static void Pass(const char *name) {
 printf("%s\"%s\"",Cases?",":"",name);Cases++;
}
static MEMORY Memory(const MODEL *m) { MEMORY x={0};x.Model=*m;return x; }
static unsigned Read(void *context,SF_U64 at,unsigned n,void *out) {
 MEMORY *m=context;unsigned index=m->Reads++;
 assert(index<4 && at==m->Model.At[index] && n==m->Model.Size[index]);
 if(m->FailRead==index+1)return 0;
 memcpy(out,m->Model.Chunk[index],n);
 if(m->CorruptRead==index+1){assert(m->CorruptByte<n);((unsigned char *)out)[m->CorruptByte]^=1;}
 return 1;
}
static void Refuse(const SF_INPUT *input,unsigned fault,const char *name) {
 MEMORY m=Memory(&Models[0]);SF_RESPONSE r;memset(&r,0xa5,sizeof(r));
 assert(OpenScmCaptureResponse(input,Read,&m,&r)==fault);
 assert(r.Fault==fault && !r.Captured && !r.Bound && !m.Reads &&
        !r.ReadAttempts && !r.BytesRequested && !r.X0 && !r.X1 && !r.X2 && !r.X3 && !r.X6);
 Pass(name);
}
int main(void) {
 printf("{\"passed\":true,\"results\":[");
 for(unsigned n=0;n<sizeof(Models)/sizeof(*Models);n++) {
  MEMORY m=Memory(&Models[n]);SF_RESPONSE r={0};const MODEL *model=&Models[n];
  assert(!OpenScmCaptureResponse(&model->In,Read,&m,&r));
  assert(r.Captured && !r.Bound && !r.Fault && r.ReadAttempts==4 && r.BytesRequested==64 && m.Reads==4);
  assert(r.X0==model->Expected[0] && r.X1==model->Expected[1] &&
         r.X2==model->Expected[2] && r.X3==model->Expected[3] && r.X6==model->Expected[4]);
  assert(r.MethodFp==model->At[1]);
  assert(OpenScmBindResponse(&r,model->ApiStatus^1,model->Result0)==SF_API_MISMATCH && !r.Bound);
  assert(OpenScmBindResponse(&r,model->ApiStatus,model->Result0^1)==SF_API_MISMATCH && !r.Bound);
  assert(!OpenScmBindResponse(&r,model->ApiStatus,model->Result0) && r.Bound && !r.Fault);
  char name[64];snprintf(name,sizeof(name),"original-frame-%u-and-API-binding",n);Pass(name);
 }
 SF_INPUT i=Models[0].In;
#define REFUSE(member,value,fault,name) do {i=Models[0].In;i.member=(value);Refuse(&i,fault,name);} while(0)
 REFUSE(CodeBound,0,SF_IDENTITY,"code-not-bound");
 REFUSE(CodeBound,2,SF_IDENTITY,"code-flag-noncanonical");
 REFUSE(StackAdmitted,0,SF_IDENTITY,"stack-not-admitted");
 REFUSE(StackAdmitted,2,SF_IDENTITY,"stack-flag-noncanonical");
 REFUSE(Image,35,SF_REQUEST,"wrong-image");
 REFUSE(Command,0x42000205,SF_REQUEST,"authentication-command-refused");
 REFUSE(Command,0x42000206,SF_REQUEST,"shutdown-command-refused");
 REFUSE(Command,0x02000202,SF_REQUEST,"wrong-command-class");
 REFUSE(ScmBase,0,SF_ARGUMENT,"null-image-base");
 REFUSE(ScmBase,i.ScmBase+1,SF_ARGUMENT,"unaligned-image-base");
 REFUSE(ScmBase,~0ULL-4095,SF_ARGUMENT,"image-overflow");
 REFUSE(Bytes,0,SF_ARGUMENT,"zero-message-length");
 REFUSE(Bytes,513,SF_ARGUMENT,"excess-message-length");
 REFUSE(StackLow,i.StackHigh,SF_BOUNDS,"empty-stack-range");
 REFUSE(StackLow,i.StackHigh+1,SF_BOUNDS,"reversed-stack-range");
 REFUSE(StackLow,i.StackHigh-0x10001,SF_BOUNDS,"excess-stack-span");
 REFUSE(StackLow,i.EntrySp+1,SF_BOUNDS,"entry-before-stack");
 REFUSE(StackHigh,i.EntrySp+0x39f,SF_BOUNDS,"caller-frame-truncated-by-one");
 REFUSE(EntrySp,~0ULL-15,SF_BOUNDS,"entry-stack-overflow");
 REFUSE(EntrySp,i.EntrySp+1,SF_CALLSITE,"unaligned-entry-stack");
 REFUSE(EntryFp,i.EntryFp+8,SF_CALLSITE,"unaligned-frame");
 REFUSE(EntryFp,i.EntryFp+16,SF_CALLSITE,"wrong-formatter-frame");
 REFUSE(Buffer,i.Buffer+1,SF_CALLSITE,"wrong-message-buffer");
 REFUSE(EntryLr,i.EntryLr+4,SF_CALLSITE,"wrong-tail-return");
 REFUSE(PrintedStatus32,0,SF_STATUS,"success-is-not-an-error");
 REFUSE(PrintedStatus32,1,SF_STATUS,"positive-interrupted-status-refused");
 REFUSE(PrintedStatus32,i.PrintedStatus32^8,SF_STATUS,"printed-low32-mismatch");
 for(unsigned frame=1;frame<=2;frame++)for(unsigned field=0;field<2;field++) {
  MEMORY m=Memory(&Models[0]);m.CorruptRead=frame;m.CorruptByte=field*8;
  SF_RESPONSE r={0};assert(OpenScmCaptureResponse(&m.Model.In,Read,&m,&r)==SF_CHAIN);
  assert(!r.Captured && !r.Bound && m.Reads==frame && r.ReadAttempts==frame);
  char name[64];snprintf(name,sizeof(name),"frame-%u-field-%u-corrupted",frame,field);Pass(name);
 }
 for(unsigned fail=1;fail<=4;fail++) {
  MEMORY m=Memory(&Models[0]);m.FailRead=fail;SF_RESPONSE r={0};
  assert(OpenScmCaptureResponse(&m.Model.In,Read,&m,&r)==SF_READ_FAILED);
  assert(!r.Captured && !r.Bound && m.Reads==fail && r.ReadAttempts==fail && r.BytesRequested<=64);
  assert(!r.X0 && !r.X1 && !r.X2 && !r.X3 && !r.X6);
  char name[64];snprintf(name,sizeof(name),"stack-read-%u-failed",fail);Pass(name);
 }
 {
  MEMORY m=Memory(&Models[0]);SF_RESPONSE r={0};i=m.Model.In;
  i.StackLow=i.EntrySp;i.StackHigh=i.EntrySp+0x3a0;
  assert(!OpenScmCaptureResponse(&i,Read,&m,&r) && m.Reads==4);Pass("exact-inclusive-extent");
 }
 {
  MEMORY m=Memory(&Models[0]);SF_RESPONSE r={0};
  assert(OpenScmCaptureResponse(NULL,Read,&m,&r)==SF_ARGUMENT && !m.Reads);Pass("null-input");
  assert(OpenScmCaptureResponse(&m.Model.In,NULL,&m,&r)==SF_ARGUMENT && !m.Reads);Pass("null-read-callback");
  assert(OpenScmCaptureResponse(&m.Model.In,Read,&m,NULL)==SF_ARGUMENT && !m.Reads);Pass("null-output");
  assert(OpenScmBindResponse(&r,m.Model.ApiStatus,m.Model.Result0)==SF_ARGUMENT);Pass("no-capture-cannot-bind");
  assert(OpenScmBindResponse(NULL,0,0)==SF_ARGUMENT);Pass("null-bind-output");
  assert(!OpenScmCaptureResponse(&m.Model.In,Read,&m,&r));r.X0=0;
  assert(OpenScmBindResponse(&r,m.Model.ApiStatus,m.Model.Result0)==SF_STATUS && !r.Bound);Pass("invalid-captured-status-refused");
 }
 printf("],\"cases\":%u}\n",Cases);return 0;
}
