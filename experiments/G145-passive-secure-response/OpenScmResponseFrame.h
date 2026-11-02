/* SPDX-License-Identifier: MIT
 * Offline prototype. Requires caller-verified SCM code identity and admitted
 * stack mapping, plus a receiver snapshot taken before C changes entry registers.
 */
#ifndef OPEN_SCM_RESPONSE_FRAME_H
#define OPEN_SCM_RESPONSE_FRAME_H
typedef unsigned long long SF_U64;
typedef unsigned SF_U32;
typedef unsigned (*SF_READ)(void *,SF_U64,unsigned,void *);
typedef struct {
 SF_U64 ScmBase,StackLow,StackHigh,EntrySp,EntryFp,EntryLr,EntryX24,Buffer,Bytes;
 SF_U32 CodeBound,StackAdmitted,Image,Command,PrintedStatus32;
} SF_INPUT;
typedef struct {
 SF_U64 X0,X1,X2,X3,X6,MethodFp;
 SF_U32 Captured,Bound,Fault,ReadAttempts,BytesRequested;
} SF_RESPONSE;
enum {
 SF_ARGUMENT=1,SF_IDENTITY=2,SF_REQUEST=4,SF_BOUNDS=8,SF_CALLSITE=16,
 SF_CHAIN=32,SF_READ_FAILED=64,SF_STATUS=128,SF_API_MISMATCH=256
};
unsigned OpenScmCaptureResponse(const SF_INPUT *,SF_READ,void *,SF_RESPONSE *);
unsigned OpenScmBindResponse(SF_RESPONSE *,SF_U64,SF_U64);
#endif
