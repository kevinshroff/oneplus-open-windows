/* Included once in the actual MMU1 owner after CaptureGlobals/Pnp declaration.
 * Actual private context grants/maps, owner mutex, D0 and live CGH producer. */
typedef struct {OSM_CONTEXT*P;CGH_NATIVE*H;}OLB_NATIVE_IO;
static int LocalCurrent(void*x,uint64_t generation,uint64_t serial){OLB_NATIVE_IO*i=x;OSM_CONTEXT*p=i->P;CGH_NATIVE*h=i->H;
 if(GmuCurrent(p,generation)||!p->Granted[0]||!p->Map[0]||osm_required_ranges[0].pa!=0x03da0000||osm_required_ranges[0].bytes!=0x40000||!h||!h->Life||h->Serial!=serial||h->Hold.serial!=serial||((!h->BootCommitted&&h->Hold.state!=(h->Hold.reset_mode?CGH_RESET_QUIESCENT:CGH_HELD))||(h->BootCommitted&&h->Hold.state!=(h->Hold.reset_mode?CGH_BOOT_RELEASED:CGH_RELEASED)))||h->Clock.Api.Interface.Context!=p||!h->Clock.Token)return -1;
 unsigned matched=0;for(unsigned k=0;k<RTL_NUMBER_OF(p->GmuSlots);k++)if(p->GmuSlots[k].Id==h->Clock.Token&&p->GmuSlots[k].Client.Context==h&&p->GmuSlots[k].Client.Pdo==h->Life->Pdo&&p->GmuSlots[k].Client.Generation==h->Generation)matched++;
 if(matched!=1)return -1;
 if(h->BootCommitted){OSMA_NATIVE_IO*r=p->RunNative;return p->RunBank&&p->RunBank->Hold==h&&p->RunBank->ProgramPinned&&r&&p->RunTag==r->Proof.Context&&r->Proof.Bank==p->RunBank&&r->Tables&&r->Tables->Session.Phase==OSMA_ACTIVE&&!r->Tables->Poisoned&&!r->Tables->Disabled&&r->Tables->References>=2&&CghNativeRuntimeCheck(h)==STATUS_SUCCESS?0:-1;}
 return CghNativeCheck(h)==STATUS_SUCCESS?0:-1;
}
static int LocalSnapshot(void*x,OSH_SNAPSHOT*s){OLB_NATIVE_IO*i=x;if(LocalCurrent(x,i->P->Generation,i->H->Serial))return -1;return CaptureGlobals(i->P,s)==STATUS_SUCCESS?0:-1;}
static int LocalSctlr(void*x,unsigned bank,uint32_t*v){OLB_NATIVE_IO*i=x;OSM_CONTEXT*p=i->P;if(i->H->BootCommitted||!v||bank<2||bank>=22||LocalCurrent(x,p->Generation,i->H->Serial))return -1;
 unsigned claimed=0;for(unsigned k=0;k<20;k++)if(p->Banks.Claim[k].State!=OLB_FREE&&p->Banks.Claim[k].Bank==bank)claimed++;
 if(claimed!=1)return -1;*v=READ_REGISTER_ULONG((PULONG)((PUCHAR)p->Map[0]+0x20000+bank*0x1000));KeMemoryBarrier();return *v==MAXULONG?-1:0;
}
static OLB_IO LocalOps(OLB_NATIVE_IO*i){OLB_IO o={i,LocalCurrent,LocalSnapshot,LocalSctlr};return o;}
static NTSTATUS LocalStatus(enum olb_status s){return s==OLB_OK?STATUS_SUCCESS:s==OLB_FULL?STATUS_INSUFFICIENT_RESOURCES:s==OLB_BUSY?STATUS_DEVICE_BUSY:s==OLB_CURRENT?STATUS_INVALID_DEVICE_STATE:STATUS_DEVICE_CONFIGURATION_ERROR;}
static OSM_CONTEXT*LocalContext(PDEVICE_OBJECT fdo){if(!fdo||fdo->DriverObject->MajorFunction[IRP_MJ_PNP]!=Pnp)return NULL;OSM_CONTEXT*p=((OSM_EXTENSION*)fdo->DeviceExtension)->P;return p&&p->Fdo==fdo?p:NULL;}
static NTSTATUS LocalEnter(OLB_NATIVE*b,OSM_CONTEXT**out){if(!b||!b->Referenced||!b->Fdo||!b->Hold||!b->Id||KeGetCurrentIrql()!=PASSIVE_LEVEL)return STATUS_INVALID_PARAMETER;OSM_CONTEXT*p=LocalContext(b->Fdo);if(!p)return STATUS_INVALID_DEVICE_STATE;NTSTATUS st=IoAcquireRemoveLock(&p->Remove,b);if(st!=STATUS_SUCCESS)return st;BrokerLock(p);*out=p;return STATUS_SUCCESS;}
static VOID LocalLeave(OSM_CONTEXT*p,OLB_NATIVE*b){BrokerUnlock(p);IoReleaseRemoveLock(&p->Remove,b);}
NTSTATUS OlbNativeReserve(OLB_NATIVE*b,PDEVICE_OBJECT fdo,CGH_NATIVE*h){
 if(!b||b->Referenced||b->Id||!h||h->BootCommitted||KeGetCurrentIrql()!=PASSIVE_LEVEL)return STATUS_INVALID_PARAMETER;OSM_CONTEXT*p=LocalContext(fdo);if(!p)return STATUS_INVALID_DEVICE_STATE;NTSTATUS st=IoAcquireRemoveLock(&p->Remove,b);if(st!=STATUS_SUCCESS)return st;BrokerLock(p);
 OLB_NATIVE_IO n={p,h};OLB_IO io=LocalOps(&n);ULONGLONG id=0;st=LocalStatus(OlbReserve(&p->Banks,&io,p->Generation,h->Serial,&id));
 if(st==STATUS_SUCCESS){ObReferenceObject(fdo);b->Fdo=fdo;b->Hold=h;b->Id=id;b->Generation=p->Generation;b->StopSerial=h->Serial;b->Referenced=TRUE;p->BankClaims++;}
 BrokerUnlock(p);IoReleaseRemoveLock(&p->Remove,b);return st;
}
NTSTATUS OlbNativeQualify(OLB_NATIVE*b,OLB_CLAIM*out){if(!b||!b->Hold||b->Hold->BootCommitted)return STATUS_INVALID_DEVICE_STATE;if(!out)return STATUS_INVALID_PARAMETER;OSM_CONTEXT*p;NTSTATUS st=LocalEnter(b,&p);if(st!=STATUS_SUCCESS)return st;OLB_NATIVE_IO n={p,b->Hold};OLB_IO io=LocalOps(&n);st=LocalStatus(OlbQualify(&p->Banks,&io,b->Id));if(st==STATUS_SUCCESS)st=LocalStatus(OlbCheck(&p->Banks,&io,b->Id,out));LocalLeave(p,b);return st;}
static NTSTATUS LocalCheckRequest(OLB_NATIVE*b,const OSMA_REQUEST*q,BOOLEAN pin){
 if(pin&&b->Hold&&b->Hold->BootCommitted)return STATUS_INVALID_DEVICE_STATE;
 if(!q||q->Proof.Bank!=b||q->Proof.StopSerial!=b->StopSerial)return STATUS_INVALID_PARAMETER;OSM_CONTEXT*p;NTSTATUS st=LocalEnter(b,&p);if(st!=STATUS_SUCCESS)return st;OLB_NATIVE_IO n={p,b->Hold};OLB_IO io=LocalOps(&n);OLB_CLAIM c;
 st=LocalStatus(b->ProgramPinned?OlbCheckPinned(&p->Banks,&io,b->Id,&c):OlbCheck(&p->Banks,&io,b->Id,&c));
 if(st==STATUS_SUCCESS&&(q->Bank!=c.Bank||q->Asid!=c.Asid||q->Slot!=c.Slot))st=STATUS_INVALID_PARAMETER;
 if(st==STATUS_SUCCESS&&pin){st=LocalStatus(OlbPinProgramming(&p->Banks,&io,b->Id));if(st==STATUS_SUCCESS)b->ProgramPinned=TRUE;}
 LocalLeave(p,b);return st;
}
NTSTATUS OlbNativeCheckBank(OLB_NATIVE*b,const OSMA_REQUEST*q){return !b?STATUS_INVALID_PARAMETER:LocalCheckRequest(b,q,FALSE);}
NTSTATUS OlbNativePinProgramming(OLB_NATIVE*b,const OSMA_REQUEST*q){return !b?STATUS_INVALID_PARAMETER:LocalCheckRequest(b,q,TRUE);}
NTSTATUS OlbNativeBindRequest(OLB_NATIVE*b,OSMA_REQUEST*q){if(!b||!q||!b->Hold||b->Hold->BootCommitted)return STATUS_INVALID_PARAMETER;OSM_CONTEXT*p;NTSTATUS st=LocalEnter(b,&p);if(st!=STATUS_SUCCESS)return st;OLB_NATIVE_IO n={p,b->Hold};OLB_IO io=LocalOps(&n);OLB_CLAIM c;st=LocalStatus(OlbCheck(&p->Banks,&io,b->Id,&c));if(st==STATUS_SUCCESS){q->Bank=c.Bank;q->Asid=c.Asid;q->Slot=c.Slot;q->Proof.Bank=b;q->Proof.StopSerial=c.StopSerial;}LocalLeave(p,b);return st;}
NTSTATUS OlbNativeReleaseUnpublished(OLB_NATIVE*b){OSM_CONTEXT*p;NTSTATUS st=LocalEnter(b,&p);if(st!=STATUS_SUCCESS)return st;if(b->ProgramPinned||!p->BankClaims||p->Fault.Map[0]||p->Fault.Map[1])st=STATUS_DEVICE_BUSY;else{OLB_NATIVE_IO n={p,b->Hold};OLB_IO io=LocalOps(&n);st=LocalStatus(OlbReleaseUnpublished(&p->Banks,&io,b->Id));if(st==STATUS_SUCCESS){p->BankClaims--;PDEVICE_OBJECT fdo=b->Fdo;LocalLeave(p,b);RtlZeroMemory(b,sizeof(*b));ObDereferenceObject(fdo);return STATUS_SUCCESS;}}LocalLeave(p,b);return st;}

NTSTATUS OlbNativeReserveFromHold(OLB_NATIVE*b,CGH_NATIVE*h){if(!h||!h->Clock.Bound||!h->Clock.File||!h->Clock.Token||KeGetCurrentIrql()!=PASSIVE_LEVEL)return STATUS_DEVICE_NOT_READY;PDEVICE_OBJECT fdo=IoGetRelatedDeviceObject(h->Clock.File);return OlbNativeReserve(b,fdo,h);}
static NTSTATUS LocalApiReserve(PVOID x,OLB_NATIVE*b,CGH_NATIVE*h){OSM_CONTEXT*p=x;if(!h||h->Clock.Api.Interface.Context!=p)return STATUS_ACCESS_DENIED;return OlbNativeReserve(b,p->Fdo,h);}
static int LocalApiBound(PVOID x,OLB_NATIVE*b){OSM_CONTEXT*p=x;return b&&b->Referenced&&b->Fdo==p->Fdo;}
static NTSTATUS LocalApiQualify(PVOID x,OLB_NATIVE*b,OLB_CLAIM*c){return LocalApiBound(x,b)?OlbNativeQualify(b,c):STATUS_INVALID_PARAMETER;}
static NTSTATUS LocalApiBind(PVOID x,OLB_NATIVE*b,OSMA_REQUEST*q){return LocalApiBound(x,b)?OlbNativeBindRequest(b,q):STATUS_INVALID_PARAMETER;}
static NTSTATUS LocalApiCheck(PVOID x,OLB_NATIVE*b,const OSMA_REQUEST*q){return LocalApiBound(x,b)?OlbNativeCheckBank(b,q):STATUS_INVALID_PARAMETER;}
static NTSTATUS LocalApiPin(PVOID x,OLB_NATIVE*b,const OSMA_REQUEST*q){return LocalApiBound(x,b)?OlbNativePinProgramming(b,q):STATUS_INVALID_PARAMETER;}
static NTSTATUS LocalApiRelease(PVOID x,OLB_NATIVE*b){return LocalApiBound(x,b)?OlbNativeReleaseUnpublished(b):STATUS_INVALID_PARAMETER;}
