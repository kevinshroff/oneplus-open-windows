#!/usr/bin/env python3
"""Exercise the actual G779 DDI body; stub only the queue acceptance boundary."""
from pathlib import Path
import os, subprocess, tempfile
W=Path(__file__).resolve().parent
source=(W.parent.parent/'drivers/gpu/gpu-wddm-bridge-G779/source/ddi.c').read_text()
start=source.index('static NTSTATUS APIENTRY TgSubmitCommand(')
brace=source.index('{',start);depth=1;end=brace+1
while depth:
    depth+=(source[end]=='{')-(source[end]=='}');end+=1
body=source[start:end]
prefix=r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
typedef int32_t NTSTATUS;
typedef uint32_t ULONG;
typedef unsigned char UCHAR;
typedef void *HANDLE;
typedef struct {ULONG LastSubmittedFence,LastCompletedFence;} TGPU_ADAPTER;
typedef struct {
 const void *pDmaBufferPrivateData;
 ULONG DmaBufferPrivateDataSubmissionEndOffset,DmaBufferPrivateDataSubmissionStartOffset;
 ULONG SubmissionFenceId,DmaBufferSubmissionEndOffset,DmaBufferSubmissionStartOffset;
 struct {ULONG Value;} Flags;
} DXGKARG_SUBMITCOMMAND;
#define APIENTRY
#define NT_SUCCESS(x) ((x)>=0)
#define STATUS_SUCCESS 0
#define LogPrint(...) ((void)0)
static NTSTATUS queue_status;
static unsigned calls,completions;
static const void *seen;
static ULONG seen_bytes,seen_fence;
static TGPU_ADAPTER *target;
static NTSTATUS EngSubmit(const void *p,ULONG n,ULONG f){assert(target->LastSubmittedFence==f);calls++;seen=p;seen_bytes=n;seen_fence=f;return queue_status;}
/* Old behavior increments this; tests must reject all fabricated completions. */
void CompleteFence(TGPU_ADAPTER *a,ULONG f){completions++;a->LastCompletedFence=f;}
'''
suffix=r'''
int main(void){
 TGPU_ADAPTER a={7,5};target=&a;unsigned char payload[32]={0};
 DXGKARG_SUBMITCOMMAND q={0};q.pDmaBufferPrivateData=payload;
 q.DmaBufferPrivateDataSubmissionStartOffset=4;q.DmaBufferPrivateDataSubmissionEndOffset=20;
 q.SubmissionFenceId=9;
 const NTSTATUS failures[]={(NTSTATUS)0xc00000a3u,(NTSTATUS)0xc0000017u};
 for(unsigned i=0;i<2;i++){
  queue_status=failures[i];assert(TgSubmitCommand(&a,&q)==failures[i]);
  assert(a.LastSubmittedFence==9&&a.LastCompletedFence==5&&!completions);
 }
 queue_status=0;assert(!TgSubmitCommand(&a,&q));
 assert(a.LastSubmittedFence==9&&a.LastCompletedFence==5&&!completions);
 assert(calls==3&&seen==payload+4&&seen_bytes==16&&seen_fence==9);
 puts("queue-rejection/acceptance: 3 cases passed; native_evidence=false");
}
'''
with tempfile.TemporaryDirectory(prefix='g1315-') as tmp:
    c=Path(tmp)/'submit.c';exe=Path(tmp)/'submit';c.write_text(prefix+body+suffix)
    subprocess.run([os.environ.get('CC','clang'),'-std=c11','-Wall','-Wextra','-Werror',
                    '-fsanitize=address,undefined','-fno-sanitize-recover=all',str(c),'-o',str(exe)],check=True)
    subprocess.run([str(exe)],check=True)
