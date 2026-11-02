/* Private actual MMU1 namespace-writer interval; distinct from BrokerLock. */
static NTSTATUS NsEnterApi(PVOID x,OLB_NATIVE*b,PVOID fault,PVOID tag,OPEN_NS_SCOPE*out){
 OSM_CONTEXT*p=x;if(!tag||!out||!b||KeGetCurrentIrql()!=PASSIVE_LEVEL)return STATUS_INVALID_PARAMETER;RtlZeroMemory(out,sizeof(*out));NTSTATUS st=IoAcquireRemoveLock(&p->Remove,tag);if(st!=STATUS_SUCCESS)return st;
 LARGE_INTEGER timeout;timeout.QuadPart=-500000;st=KeWaitForSingleObject(&p->NsMutex,Executive,KernelMode,FALSE,&timeout);if(st!=STATUS_SUCCESS){IoReleaseRemoveLock(&p->Remove,tag);return st;}
 if(p->NsThread||p->NsSequence==MAXULONGLONG||InterlockedCompareExchange(&p->NsRevoked,0,0)){st=STATUS_DEVICE_BUSY;goto fail;}
 OSMA_REQUEST q;RtlZeroMemory(&q,sizeof(q));st=OlbNativeBindRequest(b,&q);if(st!=STATUS_SUCCESS&&b->ProgramPinned){/* real canonical pinned claim, no cold reclassification */
  OLB_NATIVE_IO n={p,b->Hold};OLB_IO io=LocalOps(&n);OLB_CLAIM c;BrokerLock(p);st=LocalStatus(OlbCheckPinned(&p->Banks,&io,b->Id,&c));BrokerUnlock(p);if(st==STATUS_SUCCESS){q.Bank=c.Bank;q.Asid=c.Asid;q.Slot=c.Slot;q.Proof.StopSerial=c.StopSerial;}}
 if(st!=STATUS_SUCCESS)goto fail;q.Proof.Fault=fault;st=FaultCheckApi(p,b,fault,&q);if(st!=STATUS_SUCCESS)goto fail;
 BrokerLock(p);if(Frame(p,p->Generation)||!p->D0Ref||p->StopPending||p->RemovePending||!p->Granted[0]||p->BankClaims!=1||InterlockedCompareExchange(&p->NsRevoked,0,0)){BrokerUnlock(p);st=STATUS_INVALID_DEVICE_STATE;goto fail;}
 p->NsThread=PsGetCurrentThread();p->NsTag=tag;p->NsBank=b;p->NsFault=fault;p->NsToken=++p->NsSequence;p->NsGeneration=p->Generation;
 out->Token=p->NsToken;out->ProviderGeneration=p->Generation;out->Grant.Count=1;out->Grant.List[0].PartialResourceList.Version=1;out->Grant.List[0].PartialResourceList.Revision=1;out->Grant.List[0].PartialResourceList.Count=1;out->Grant.List[0].PartialResourceList.PartialDescriptors[0]=p->NsGrant;
 BrokerUnlock(p);return STATUS_SUCCESS;
fail:KeReleaseMutex(&p->NsMutex,FALSE);IoReleaseRemoveLock(&p->Remove,tag);return st;
}
static NTSTATUS NsCheckApi(PVOID x,OLB_NATIVE*b,PVOID fault,PVOID tag,const OPEN_NS_SCOPE*s){OSM_CONTEXT*p=x;
 if(!s||!s->Token||p->NsThread!=PsGetCurrentThread()||p->NsTag!=tag||p->NsBank!=b||p->NsFault!=fault||p->NsToken!=s->Token||p->NsGeneration!=s->ProviderGeneration||p->Generation!=s->ProviderGeneration||InterlockedCompareExchange(&p->NsRevoked,0,0)||KeGetCurrentIrql()!=PASSIVE_LEVEL||s->Grant.Count!=1||s->Grant.List[0].PartialResourceList.Count!=1||RtlCompareMemory(&s->Grant.List[0].PartialResourceList.PartialDescriptors[0],&p->NsGrant,sizeof(p->NsGrant))!=sizeof(p->NsGrant))return STATUS_INVALID_DEVICE_STATE;
 OSMA_REQUEST q;RtlZeroMemory(&q,sizeof(q));q.Proof.StopSerial=b->StopSerial;q.Proof.Fault=fault;
 OLB_NATIVE_IO n={p,b->Hold};OLB_IO io=LocalOps(&n);OLB_CLAIM c;BrokerLock(p);NTSTATUS st=LocalStatus(b->ProgramPinned?OlbCheckPinned(&p->Banks,&io,b->Id,&c):OlbCheck(&p->Banks,&io,b->Id,&c));BrokerUnlock(p);
 if(st==STATUS_SUCCESS){q.Bank=c.Bank;q.Asid=c.Asid;q.Slot=c.Slot;st=FaultCheckApi(p,b,fault,&q);}return st;
}
/* v5 only. NsMutex + remove-lock tag keep all objects/code pinned; this
 * cheap check observes asynchronous revocation before a bounded copy word.
 * No GmuCurrent/osm_witness/LocalCurrent callback or register access here. */
static NTSTATUS NsCheckFastApi(PVOID x,OLB_NATIVE*b,PVOID fault,PVOID tag,const OPEN_NS_SCOPE*s){
 OSM_CONTEXT*p=x;if(!p||!b||!s||!tag||KeGetCurrentIrql()!=PASSIVE_LEVEL)return STATUS_INVALID_PARAMETER;
 if(InterlockedCompareExchange(&p->NsRevoked,0,0)||InterlockedCompareExchange(&p->Fault.Journal.Fatal,0,0)||!InterlockedCompareExchange(&p->Fault.Armed,0,0))return STATUS_DEVICE_NOT_READY;
 BrokerLock(p);NTSTATUS st=STATUS_INVALID_DEVICE_STATE;OF_OWNER*f=&p->Fault;CGH_NATIVE*h=b->Hold;
 if(Frame(p,p->Generation)||!p->D0Ref||p->StopPending||p->RemovePending||!p->Granted[0]||!p->Map[0]||p->Banks.Generation!=p->Generation||!p->NsToken||p->NsThread!=PsGetCurrentThread()||p->NsTag!=tag||p->NsBank!=b||p->NsFault!=fault||p->NsToken!=s->Token||p->NsGeneration!=s->ProviderGeneration||p->Generation!=s->ProviderGeneration||InterlockedCompareExchange(&p->NsRevoked,0,0)||s->Grant.Count!=1||s->Grant.List[0].PartialResourceList.Count!=1||RtlCompareMemory(&s->Grant.List[0].PartialResourceList.PartialDescriptors[0],&p->NsGrant,sizeof(p->NsGrant))!=sizeof(p->NsGrant))goto done;
 if(!FaultBinding(p,b)||!b->ProgramPinned||b->Generation!=p->Generation||!h||h->BootCommitted||!h->Life||!h->ScopeHeld||h->Thread!=PsGetCurrentThread()||h->Life->HeldThread!=h->Thread||h->Life->Generation!=h->Generation||InterlockedCompareExchange(&h->Life->Inhibit,0,0)||h->Poisoned||!h->Hold.reset_mode||h->Hold.state!=CGH_RESET_QUIESCENT||h->Hold.owned||h->Hold.attempted||b->StopSerial!=h->Serial||h->Hold.serial!=h->Serial||h->Clock.Api.Interface.Context!=p||!h->Clock.Token)goto done;
 if(p->Lease.state!=OSM_ACTIVE||p->Lease.generation!=p->Generation||p->Lease.refs!=p->Clients+1||p->Gmu.state!=GMC_HELD||p->Gmu.generation!=p->Generation||!p->GmuClients||p->Gmu.refs!=p->GmuClients)goto done;
 if(fault!=f||f->Bank!=b||f->Generation!=p->Generation||!f->GrantsValid||!f->Map[0]||!f->Map[1]||!f->Interrupt[0]||!f->Interrupt[1]||(p->GpuUser.Qualified&&(!f->Map[2]||!f->Interrupt[2]))||f->KnownMask!=(p->GpuUser.Qualified?7u:3u)||f->UncertainMask||f->Retain||f->Connecting||!InterlockedCompareExchange(&f->Armed,0,0)||InterlockedCompareExchange(&f->Journal.Fatal,0,0))goto done;
 unsigned clients=0,claims=0;for(unsigned i=0;i<RTL_NUMBER_OF(p->GmuSlots);i++){OSM_CLIENT_SLOT*c=&p->GmuSlots[i];if(c->Id==h->Clock.Token&&c->Client.Context==h&&c->Client.Pdo==h->Life->Pdo&&c->Client.Generation==h->Generation)clients++;}
 for(unsigned i=0;i<RTL_NUMBER_OF(p->Banks.Claim);i++){OLB_CLAIM*c=&p->Banks.Claim[i];if(c->Id==b->Id&&c->State==OLB_PROGRAM_PINNED&&c->Generation==p->Generation&&c->StopSerial==h->Serial&&c->Bank==2&&c->Asid==2&&c->Slot==0)claims++;}
 if(clients==1&&claims==1&&!InterlockedCompareExchange(&p->NsRevoked,0,0)&&!InterlockedCompareExchange(&f->Journal.Fatal,0,0)&&InterlockedCompareExchange(&f->Armed,0,0))st=STATUS_SUCCESS;
 done:BrokerUnlock(p);return st;
}
static NTSTATUS NsLeaveApi(PVOID x,PVOID tag,OPEN_NS_SCOPE*s){OSM_CONTEXT*p=x;
 if(!s||!s->Token||KeGetCurrentIrql()!=PASSIVE_LEVEL||p->NsThread!=PsGetCurrentThread()||p->NsTag!=tag||p->NsToken!=s->Token)return STATUS_INVALID_DEVICE_STATE;
 /* Actual owner may release only its software interval even after D0/IRQ
  * invalidation; hardware/maps/tables remain governed by sticky journals. */
 BrokerLock(p);
 NTSTATUS st=STATUS_SUCCESS;
 if(InterlockedCompareExchange(&p->NsRevoked,0,0)||p->NsGeneration!=p->Generation)st=STATUS_INVALID_DEVICE_STATE;
 if(p->Fault.Retain||InterlockedCompareExchange(&p->Fault.Journal.Fatal,0,0)){FaultDisconnectObjects(&p->Fault);st=STATUS_DEVICE_HARDWARE_ERROR;}
 p->NsThread=NULL;p->NsTag=NULL;p->NsBank=NULL;p->NsFault=NULL;p->NsToken=0;BrokerUnlock(p);RtlZeroMemory(s,sizeof(*s));KeReleaseMutex(&p->NsMutex,FALSE);IoReleaseRemoveLock(&p->Remove,tag);return st;
}
/* Register only the actual successful native constructor/session under its
 * existing cold namespace and fault owner. This does not release the halt. */
static NTSTATUS NsPromoteRuntimeApi(PVOID x,OLB_NATIVE*b,PVOID fault,PVOID tag,const OPEN_NS_SCOPE*s,OSMA_NATIVE_IO*n){
 OSM_CONTEXT*p=x;NTSTATUS st=NsCheckApi(x,b,fault,tag,s);if(st!=STATUS_SUCCESS)return st;
 if(!n||n->Pdo!=p->Pdo||n->Proof.Context!=tag||n->Proof.Bank!=b||n->Proof.Fault!=fault||!n->Base||!n->Tables||!b->ProgramPinned||b->Hold->BootCommitted)return STATUS_INVALID_DEVICE_STATE;
 OSMA_TABLE_BINDING*t=n->Tables;if(t->References<2||t->Poisoned||t->Disabled||!t->ActivationAttempted||t->Session.Phase!=OSMA_ACTIVE||t->Session.IoIdentity!=n||t->Session.BoundProof.Context!=tag||t->Session.BoundProof.Tables!=t||t->Session.Bank!=n->Bank||t->Session.Asid!=n->Bank||t->Session.Slot!=n->Slot||!t->Plan.count||t->Plan.count>G321_MAX_EXTENTS)return STATUS_INVALID_DEVICE_STATE;
 for(ULONG i=0;i<t->Plan.count;i++)if(!t->Buffer[i].Mapped||!t->Buffer[i].MapAttempted)return STATUS_INVALID_DEVICE_STATE;
 BrokerLock(p);if(p->RunNative||p->NsTag!=tag||p->NsBank!=b||p->NsToken!=s->Token||InterlockedCompareExchange(&p->NsRevoked,0,0)){BrokerUnlock(p);return STATUS_DEVICE_BUSY;}p->RunNative=n;p->RunBank=b;p->RunTag=tag;BrokerUnlock(p);return STATUS_SUCCESS;
}
