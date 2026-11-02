/* Exact retained G515 constructor/rundown bodies only. Legacy direct-clock
 * DDI/Current/HAL gates are deliberately not linked into the new CGH owner. */
#include <ntifs.h>
#include "g515_lifecycle.h"
static NTSTATUS Lock(G515_LIFE*l){LARGE_INTEGER t;t.QuadPart=-500000;if(!l||!l->Initialized||KeGetCurrentIrql()!=PASSIVE_LEVEL)return STATUS_INVALID_DEVICE_STATE;return KeWaitForSingleObject(&l->Lock,Executive,KernelMode,FALSE,&t);}
NTSTATUS G515Initialize(G515_LIFE*l,PDEVICE_OBJECT pdo){
 if(!l||!pdo||KeGetCurrentIrql()!=PASSIVE_LEVEL)return STATUS_INVALID_PARAMETER;
 RtlZeroMemory(l,sizeof(*l));KeInitializeMutex(&l->Lock,0);l->Initialized=TRUE;l->Inhibit=1;l->Pdo=pdo;ObReferenceObject(pdo);
 l->Requested=PowerDeviceUnspecified;l->Missing=31;l->Status=STATUS_DEVICE_NOT_READY;return STATUS_SUCCESS;
}
NTSTATUS G515Revoke(G515_LIFE*l,BOOLEAN remove){
 if(!l||!l->Initialized)return STATUS_INVALID_DEVICE_STATE;
 InterlockedExchange(&l->Inhibit,1);NTSTATUS s=Lock(l);if(s!=STATUS_SUCCESS)return s;
 if(l->HeldThread){KeReleaseMutex(&l->Lock,FALSE);return STATUS_DEVICE_BUSY;}
 /* The mutex joins an actual outstanding scope. Generation changes only
  * after its owner leaves. No physical/DMA stop is inferred from this join. */
 l->StartObserved=FALSE;l->OsD0Candidate=FALSE;l->PostEbsObserved=FALSE;if(remove)l->Removed=TRUE;
 if(l->Generation!=MAXULONGLONG)l->Generation++;else s=STATUS_INTEGER_OVERFLOW;
 l->Status=s;KeReleaseMutex(&l->Lock,FALSE);return s;
}
NTSTATUS G515Dispose(G515_LIFE*l){NTSTATUS s=G515Revoke(l,TRUE);if(s!=STATUS_SUCCESS)return s;if(l->Pdo)ObDereferenceObject(l->Pdo);l->Pdo=NULL;return STATUS_SUCCESS;}
