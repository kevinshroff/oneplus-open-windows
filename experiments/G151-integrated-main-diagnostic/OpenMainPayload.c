/* SPDX-License-Identifier: MIT */
#include <Uefi.h>
#include <Library/BaseMemoryLib.h>
#include "OpenMainPayload.h"
#include "OpenMainPayloadPlan.h"
#include "OpenSha256.h"
_Static_assert(sizeof(OMP_EXTENT_RESULT)==72,"fixed extent result ABI");
_Static_assert(sizeof(OMP_REPORT)==6536,"fixed main-payload result ABI");
_Static_assert(sizeof(mMainPlan)/sizeof(*mMainPlan)==OMP_EXTENTS,"fixed loader plan");

STATIC EFI_STATUS Fail(OMP_CHECKER *c,UINT32 why,EFI_STATUS status,UINT64 address){
 OMP_REPORT *r=&c->Report;r->Fault|=why;r->FailureAddress=address;
 if(r->Phase==OMP_DATA&&r->CurrentIndex<OMP_EXTENTS){
  r->Extents[r->CurrentIndex].Status=status;r->Extents[r->CurrentIndex].FailureAddress=address;
 }
 return status;
}
STATIC EFI_STATUS Own(OMP_CHECKER *c,UINT64 address){
 c->Report.OwnerChecks++;
 unsigned ok=c->Owner(c->Context);
 if(c->Report.Fault&OMP_REENTRANT)return Fail(c,OMP_REENTRANT,EFI_ACCESS_DENIED,address);
 return ok==1?EFI_SUCCESS:Fail(c,OMP_OWNER,EFI_ACCESS_DENIED,address);
}
STATIC EFI_STATUS Admit(OMP_CHECKER *c,BOOLEAN post){
 c->Report.AdmissionCalls++;
 unsigned ok=c->Admit(c->Context);
 if(c->Report.Fault&OMP_REENTRANT)return Fail(c,OMP_REENTRANT,EFI_ACCESS_DENIED,0);
 return ok==1?EFI_SUCCESS:Fail(c,post?OMP_POST_ADMISSION:OMP_ADMISSION,EFI_ACCESS_DENIED,0);
}
EFI_STATUS OpenMainPayloadInit(OMP_CHECKER *c,OMP_READ read,OMP_PREDICATE admit,OMP_PREDICATE owner,VOID *context){
 (VOID)OpenShaAll; /* Keep the inherited streaming/all-at-once core unchanged. */
 if(!c||!read||!admit||!owner||!context)return EFI_INVALID_PARAMETER;
 if(c->Initialized)return EFI_ALREADY_STARTED;
 ZeroMem(c,sizeof(*c));c->Initialized=1;c->Read=read;c->Admit=admit;c->Owner=owner;c->Context=context;
 c->Report.Size=sizeof(c->Report);c->Report.Version=1;c->Report.Status=EFI_NOT_READY;c->Report.CurrentIndex=MAX_UINT32;
 for(UINT32 i=0;i<OMP_EXTENTS;i++){
  c->Report.Extents[i].Index=i;c->Report.Extents[i].Kind=mMainPlan[i].Kind;c->Report.Extents[i].Status=EFI_NOT_READY;
 }
 return EFI_SUCCESS;
}
EFI_STATUS OpenMainPayloadVerify(OMP_CHECKER *c){
 EFI_STATUS s;OMP_REPORT *r;
 if(!c||c->Initialized!=1||!c->Read||!c->Admit||!c->Owner||!c->Context)return EFI_INVALID_PARAMETER;
 if(c->Busy){c->Report.Fault|=OMP_REENTRANT;return EFI_ACCESS_DENIED;}
 if(c->Report.Attempted)return EFI_ALREADY_STARTED;
 c->Report.Attempted=1;c->Busy=1;r=&c->Report;r->Phase=OMP_PRE;
 s=Own(c,0);if(s)goto Done;
 s=Admit(c,FALSE);if(s)goto Done;
 s=Own(c,0);if(s)goto Done;
 r->Phase=OMP_DATA;
 for(UINT32 i=0;i<OMP_EXTENTS;i++){
  CONST OMP_PLAN *p=&mMainPlan[i];OMP_EXTENT_RESULT *v=&r->Extents[i];OPEN_SHA256 hash;
  UINT64 offset=0;r->CurrentIndex=i;
  if(p->Kind==1)OpenShaInit(&hash);
  while(offset<p->Bytes){
   UINTN n=(UINTN)(p->Bytes-offset);if(n>OMP_CHUNK)n=OMP_CHUNK;
   UINT64 address=p->Base+offset;
   s=Own(c,address);if(s)goto Done;
   /* Poison the private buffer so a declined/incomplete producer cannot reuse
    * a previous zero tail. The read contract still belongs to the adapter. */
   SetMem(c->Scratch,sizeof(c->Scratch),0xa5);
   r->LastAddress=address;r->LastRequest=n;r->ReadCalls++;
   UINTN actual=n;EFI_STATUS api=c->Read(c->Context,address,&actual,c->Scratch);
   r->LastReadStatus=api;r->LastActual=actual;
   if(r->Fault&OMP_REENTRANT){s=Fail(c,OMP_REENTRANT,EFI_ACCESS_DENIED,address);goto Done;}
   if(api!=EFI_SUCCESS){s=Fail(c,OMP_READ_ERROR,EFI_DEVICE_ERROR,address);goto Done;}
   if(actual!=n){s=Fail(c,OMP_READ_SIZE,EFI_BAD_BUFFER_SIZE,address);goto Done;}
   s=Own(c,address);if(s)goto Done;
   r->ReadBytes+=n;v->ReadBytes+=n;
   if(p->Kind==1)OpenShaUpdate(&hash,c->Scratch,n);
   else for(UINTN k=0;k<n;k++)if(c->Scratch[k]){s=Fail(c,OMP_ZERO,EFI_SECURITY_VIOLATION,address+k);goto Done;}
   offset+=n;
  }
  if(p->Kind==1){
   OpenShaFinal(&hash,v->Digest);
   if(CompareMem(v->Digest,p->Digest,sizeof(p->Digest))){s=Fail(c,OMP_HASH,EFI_SECURITY_VIOLATION,p->Base);goto Done;}
   r->CompletedFiles++;
  }else r->CompletedZeroTails++;
  v->Complete=1;v->Status=EFI_SUCCESS;r->CompletedExtents++;r->VerifiedBytes+=p->Bytes;
 }
 r->Phase=OMP_POST;r->CurrentIndex=MAX_UINT32;
 s=Own(c,0);if(s)goto Done;
 s=Admit(c,TRUE);if(s)goto Done;
 s=Own(c,0);if(s)goto Done;
 r->Phase=OMP_DONE;r->Complete=1;s=EFI_SUCCESS;
Done:
 r->Status=s;c->Busy=0;return s;
}
