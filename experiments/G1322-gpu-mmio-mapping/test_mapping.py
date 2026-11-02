#!/usr/bin/env python3
"""Exercise actual G482 mapping admission/selection/rollback with host callbacks."""
from pathlib import Path
import os,subprocess,tempfile
W=Path(__file__).resolve().parent
S=W.parent/'G1287-cold-aperture/reference/runtime'
source=(S/'g482_resources.c').read_text()
body=source[source.index('static const ULONGLONG Base'):source.index('NTSTATUS G482Release')]
prefix=r'''
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
typedef uint32_t ULONG;typedef uint64_t ULONGLONG;typedef int64_t LONGLONG;
typedef int32_t NTSTATUS;typedef uint8_t BOOLEAN;typedef void VOID;
typedef void *PVOID,*PDEVICE_OBJECT;
#define TRUE 1
#define FALSE 0
#define PASSIVE_LEVEL 0
#define STATUS_SUCCESS 0
#define STATUS_INVALID_DEVICE_STATE (-1)
#define STATUS_RESOURCE_TYPE_NOT_FOUND (-2)
#define STATUS_DEVICE_CONFIGURATION_ERROR (-3)
#define STATUS_INSUFFICIENT_RESOURCES (-4)
#define PAGE_READWRITE 4u
#define PAGE_NOCACHE 0x200u
#define PAGE_WRITECOMBINE 0x400u
#define DPFLTR_IHVVIDEO_ID 0
#define DPFLTR_INFO_LEVEL 4
#define CmResourceTypeMemory 3
#define CM_RESOURCE_MEMORY_READ_WRITE 0
#define CmResourceShareDeviceExclusive 1
#define CmResourceShareDriverExclusive 2
#define RtlZeroMemory(p,n) memset(p,0,n)
typedef struct {LONGLONG QuadPart;} PHYSICAL_ADDRESS;
typedef struct {ULONG Type,Flags,ShareDisposition;struct {struct {PHYSICAL_ADDRESS Start;ULONG Length;} Memory;}u;} CM_PARTIAL_RESOURCE_DESCRIPTOR,*PCM_PARTIAL_RESOURCE_DESCRIPTOR;
typedef struct {ULONG Count;CM_PARTIAL_RESOURCE_DESCRIPTOR PartialDescriptors[16];} CM_PARTIAL_RESOURCE_LIST,*PCM_PARTIAL_RESOURCE_LIST;
typedef struct {ULONG Count;struct {CM_PARTIAL_RESOURCE_LIST PartialResourceList;}List[1];} CM_RESOURCE_LIST,*PCM_RESOURCE_LIST;
enum {G482_GPU,G482_RSCC,G482_GMU_LOW,G482_GMU_HIGH,G482_PDC,G482_BANKS};
typedef struct {PVOID Cpu[G482_BANKS];PDEVICE_OBJECT Pdo;ULONG SeenMask,MappedMask,MissingMask,ObservedDescriptors;NTSTATUS Status;BOOLEAN Initialized,Bound;}G482_BINDING;
#include "g482_mmio_policy.h"
static unsigned char views[5][32];static ULONG protection[5];
static int maps,unmaps,refs,fail_at;
static int KeGetCurrentIrql(void){return PASSIVE_LEVEL;}
static void *MmMapIoSpaceEx(PHYSICAL_ADDRESS pa,ULONG n,ULONG p){(void)pa;(void)n;assert(maps<5);int i=maps++;protection[i]=p;return i==fail_at?NULL:views[i];}
static void MmUnmapIoSpace(void *p,ULONG n){(void)p;(void)n;unmaps++;}
static void ObReferenceObject(void *p){(void)p;refs++;}
#if OGO_GPU_MMIO_WRITECOMBINE
static int DbgPrintEx(int a,int b,const char *fmt,...){(void)a;(void)b;(void)fmt;return 0;}
#endif
'''
tests=r'''
static void reset(G482_BINDING *b,CM_RESOURCE_LIST *r){
 memset(protection,0,sizeof(protection));maps=unmaps=refs=0;fail_at=-1;
 G482Initialize(b);memset(r,0,sizeof(*r));r->Count=1;r->List[0].PartialResourceList.Count=5;
 for(unsigned i=0;i<5;i++){CM_PARTIAL_RESOURCE_DESCRIPTOR*d=&r->List[0].PartialResourceList.PartialDescriptors[i];d->Type=CmResourceTypeMemory;d->ShareDisposition=CmResourceShareDeviceExclusive;d->u.Memory.Start.QuadPart=(LONGLONG)Base[i];d->u.Memory.Length=Bytes[i];}
}
int main(void){
 G482_BINDING b;CM_RESOURCE_LIST r;void*pdo=(void*)(uintptr_t)1;
 reset(&b,&r);assert(G482Bind(&b,pdo,&r)==0);assert(maps==5&&unmaps==0&&refs==1&&b.Bound&&b.MappedMask==31);
 for(unsigned i=0;i<5;i++)assert(protection[i]==(PAGE_READWRITE|((OGO_GPU_MMIO_WRITECOMBINE&&i==0)?PAGE_WRITECOMBINE:PAGE_NOCACHE)));
 assert(G482Bind(&b,pdo,&r)==STATUS_INVALID_DEVICE_STATE&&maps==5);
 reset(&b,&r);r.List[0].PartialResourceList.PartialDescriptors[1]=r.List[0].PartialResourceList.PartialDescriptors[0];assert(G482Bind(&b,pdo,&r)==STATUS_DEVICE_CONFIGURATION_ERROR&&maps==0);
 reset(&b,&r);r.List[0].PartialResourceList.Count=4;assert(G482Bind(&b,pdo,&r)==STATUS_RESOURCE_TYPE_NOT_FOUND&&maps==0);
 reset(&b,&r);r.List[0].PartialResourceList.Count=6;r.List[0].PartialResourceList.PartialDescriptors[5].Type=CmResourceTypeMemory;assert(G482Bind(&b,pdo,&r)==STATUS_DEVICE_CONFIGURATION_ERROR&&maps==0);
 reset(&b,&r);r.List[0].PartialResourceList.PartialDescriptors[2].Flags=1;assert(G482Bind(&b,pdo,&r)==STATUS_DEVICE_CONFIGURATION_ERROR&&maps==0);
 reset(&b,&r);fail_at=2;assert(G482Bind(&b,pdo,&r)==STATUS_INSUFFICIENT_RESOURCES&&maps==3&&unmaps==2&&refs==0&&!b.Bound&&b.MappedMask==0);for(unsigned i=0;i<5;i++)assert(!b.Cpu[i]);
 puts("actual G482 mapping: selection, repeat refusal, duplicate/missing/extra/flags and partial-map rollback pass");return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='g1322-map-')as t:
 t=Path(t);c=t/'mapping.c';c.write_text(prefix+body+tests)
 for enabled in [0,1]:
  out=t/('mapping-'+str(enabled))
  subprocess.run([os.environ.get('CC','clang'),'-std=c11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-fno-omit-frame-pointer','-I'+str(S),'-DOGO_GPU_MMIO_WRITECOMBINE='+str(enabled),str(c),'-o',str(out)],check=True)
  subprocess.run([str(out)],check=True)
