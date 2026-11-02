/* ABI6 private GPU role. NsMutex/remove refs pin objects; never SID5 alias. */
static int GpuUserBound(OSM_CONTEXT*p,OLB_NATIVE*b,OGU_TOKEN*t){OGU_BANK*g=&p->GpuUser;return b&&t&&p->GpuUserTag==t&&p->GpuUserGmu==b&&b->Referenced&&b->Fdo==p->Fdo&&g->Qualified&&!g->Retained&&g->Generation==p->Generation&&b->Generation==p->Generation&&t->Referenced&&t->Qualified&&t->Id==g->Id&&t->Generation==g->Generation&&t->Serial==g->Serial&&t->Sid==0&&t->Bank==0&&t->Asid==0&&t->Slot==g->Slot;}
static int GpuScope(OSM_CONTEXT*p,OLB_NATIVE*b,const OPEN_NS_SCOPE*s){return s&&s->Token&&p->NsThread==PsGetCurrentThread()&&p->NsBank==b&&p->NsToken==s->Token&&p->NsGeneration==s->ProviderGeneration&&p->Generation==s->ProviderGeneration&&s->Grant.Count==1&&s->Grant.List[0].PartialResourceList.Count==1&&RtlCompareMemory(&s->Grant.List[0].PartialResourceList.PartialDescriptors[0],&p->NsGrant,sizeof(p->NsGrant))==sizeof(p->NsGrant)&&!InterlockedCompareExchange(&p->NsRevoked,0,0)&&p->Fault.KnownMask==7&&!p->Fault.UncertainMask&&!p->Fault.Connecting&&p->Fault.Bank==b&&p->Fault.Generation==p->Generation&&p->Fault.Map[2]&&p->Fault.Interrupt[2]&&InterlockedCompareExchange(&p->Fault.Armed,0,0)&&!p->Fault.Retain&&!InterlockedCompareExchange(&p->Fault.Journal.Fatal,0,0);}
static NTSTATUS GpuUserReserveApi(PVOID x,OLB_NATIVE*b,OGU_TOKEN*t){
 OSM_CONTEXT*p=x;if(!b||!t||t->Id||t->Referenced||!b->Hold||b->Hold->BootCommitted||KeGetCurrentIrql()!=PASSIVE_LEVEL)return STATUS_INVALID_PARAMETER;
 NTSTATUS st=IoAcquireRemoveLock(&p->Remove,t);if(st!=STATUS_SUCCESS)return st;BrokerLock(p);OLB_NATIVE_IO n={p,b->Hold};OLB_IO io=LocalOps(&n);OLB_CLAIM c;
 if(p->GpuUser.Id||p->GpuUserTag||p->NsToken||p->BankClaims!=1||!b->Referenced||b->Fdo!=p->Fdo||p->TokenSequence==MAXULONGLONG){st=STATUS_DEVICE_BUSY;goto out;}
 st=LocalStatus(OlbCheck(&p->Banks,&io,b->Id,&c));if(st!=STATUS_SUCCESS||c.Bank!=2||p->Banks.SlotMask!=(1u<<c.Slot)){if(st==STATUS_SUCCESS)st=STATUS_NOT_SUPPORTED;goto out;}
 p->GpuCandidateRead=TRUE;st=LocalStatus(OguReserve(&p->GpuUser,&io,p->Generation,b->StopSerial,c.Slot,++p->TokenSequence));p->GpuCandidateRead=FALSE;
 if(st==STATUS_SUCCESS){p->GpuUserTag=t;p->GpuUserGmu=b;p->Banks.SlotMask|=1u<<p->GpuUser.Slot;ObReferenceObject(p->Fdo);*t=(OGU_TOKEN){p->GpuUser.Id,p->GpuUser.Generation,p->GpuUser.Serial,0,0,0,p->GpuUser.Slot,TRUE,TRUE};}
out:BrokerUnlock(p);IoReleaseRemoveLock(&p->Remove,t);return st;
}
static NTSTATUS GpuUserCheckApi(PVOID x,OLB_NATIVE*b,OGU_TOKEN*t,const OPEN_NS_SCOPE*s){
 OSM_CONTEXT*p=x;if(!b||!t||KeGetCurrentIrql()!=PASSIVE_LEVEL)return STATUS_INVALID_PARAMETER;NTSTATUS st=IoAcquireRemoveLock(&p->Remove,t);if(st!=STATUS_SUCCESS)return st;BrokerLock(p);
 if(!GpuUserBound(p,b,t)){st=STATUS_INVALID_DEVICE_STATE;goto out;}OLB_NATIVE_IO n={p,b->Hold};OLB_IO io=LocalOps(&n);
 if(!b->Hold->BootCommitted){if(p->NsToken){st=STATUS_INVALID_DEVICE_STATE;goto out;}p->GpuCandidateRead=TRUE;st=LocalStatus(OguCheckCold(&p->GpuUser,&io));p->GpuCandidateRead=FALSE;}
 else{
  st=GpuScope(p,b,s)&&!LocalCurrent(&n,p->Generation,b->StopSerial)?STATUS_SUCCESS:STATUS_DEVICE_NOT_READY;
  if(st==STATUS_SUCCESS&&!p->GpuUser.Programming){ULONG v=READ_REGISTER_ULONG((PULONG)((PUCHAR)p->Map[0]+0x20000));KeMemoryBarrier();if(v==MAXULONG||v!=(p->GpuUser.Active?0x00c00067u:p->GpuUser.Sctlr))st=STATUS_DEVICE_BUSY;}
 }
out:if(st!=STATUS_SUCCESS&&GpuUserBound(p,b,t))p->GpuUser.Retained=1;BrokerUnlock(p);IoReleaseRemoveLock(&p->Remove,t);return st;
}
static NTSTATUS GpuUserReleaseApi(PVOID x,OLB_NATIVE*b,OGU_TOKEN*t){
 OSM_CONTEXT*p=x;if(!b||!t||KeGetCurrentIrql()!=PASSIVE_LEVEL)return STATUS_INVALID_PARAMETER;NTSTATUS st=IoAcquireRemoveLock(&p->Remove,t);if(st!=STATUS_SUCCESS)return st;BrokerLock(p);
 if(!GpuUserBound(p,b,t)||b->Hold->BootCommitted||p->NsToken||p->GpuUser.Programming||p->GpuUser.Active||p->Fault.Map[0]||p->Fault.Map[1]||p->Fault.Map[2]||p->Fault.Retain){st=STATUS_DEVICE_BUSY;goto out;}
 OLB_NATIVE_IO n={p,b->Hold};OLB_IO io=LocalOps(&n);p->GpuCandidateRead=TRUE;st=LocalStatus(OguCheckCold(&p->GpuUser,&io));p->GpuCandidateRead=FALSE;
 if(st==STATUS_SUCCESS){p->Banks.SlotMask&=~(1u<<p->GpuUser.Slot);RtlZeroMemory(&p->GpuUser,sizeof(p->GpuUser));p->GpuUserTag=NULL;p->GpuUserGmu=NULL;RtlZeroMemory(t,sizeof(*t));BrokerUnlock(p);IoReleaseRemoveLock(&p->Remove,t);ObDereferenceObject(p->Fdo);return STATUS_SUCCESS;}p->GpuUser.Retained=1;
out:BrokerUnlock(p);IoReleaseRemoveLock(&p->Remove,t);return st;
}
static int GpuTables(OSMI_TABLES*t){return t&&t->State==OSMI_BUILT&&t->PoolOrigin==0x4e435047u&&!t->ActivationQualified&&t->Config.input_bits==39&&t->Config.output_bits==36&&t->Tables.root_physical==t->Config.table_physical&&t->Tables.root_physical<(1ull<<36)&&t->Tables.mair==0xff44&&!t->Tables.upper_region;}
static NTSTATUS GpuUserPinApi(PVOID x,OLB_NATIVE*b,OGU_TOKEN*t,const OPEN_NS_SCOPE*s,OSMI_TABLES*tables){
 OSM_CONTEXT*p=x;NTSTATUS st=GpuUserCheckApi(x,b,t,s);if(st!=STATUS_SUCCESS)return st;BrokerLock(p);
 if(!GpuUserBound(p,b,t)||!GpuScope(p,b,s)||!GpuTables(tables)||p->GpuUser.Programming||p->GpuUser.Active||p->GpuTables){st=STATUS_INVALID_DEVICE_STATE;goto out;}
 OSH_SNAPSHOT a,z;if(!p->RunNative||CaptureGlobals(p,&a)!=STATUS_SUCCESS||CaptureGlobals(p,&z)!=STATUS_SUCCESS||RtlCompareMemory(&a,&z,sizeof(a))!=sizeof(a)||RtlCompareMemory(&a,&p->RunNative->Tables->Session.After,sizeof(a))!=sizeof(a)){st=STATUS_DEVICE_CONFIGURATION_ERROR;goto out;}
 p->GpuTables=tables;p->GpuUser.Root=tables->Tables.root_physical;p->GpuUser.Programming=1;st=STATUS_SUCCESS;
out:BrokerUnlock(p);return st;
}
static NTSTATUS GpuUserCommitApi(PVOID x,OLB_NATIVE*b,OGU_TOKEN*t,const OPEN_NS_SCOPE*s,OSMI_TABLES*tables){
 OSM_CONTEXT*p=x;NTSTATUS st=GpuUserCheckApi(x,b,t,s);if(st!=STATUS_SUCCESS)return st;BrokerLock(p);
 if(!GpuUserBound(p,b,t)||!GpuScope(p,b,s)||!GpuTables(tables)||p->GpuTables!=tables||!p->GpuUser.Programming||p->GpuUser.Active){st=STATUS_INVALID_DEVICE_STATE;goto out;}
 OSH_SNAPSHOT expected=p->RunNative->Tables->Session.After,a,z;expected.Smr[t->Slot]=0x80000000u;expected.S2cr[t->Slot]=0x300;
 if(CaptureGlobals(p,&a)!=STATUS_SUCCESS||CaptureGlobals(p,&z)!=STATUS_SUCCESS||RtlCompareMemory(&a,&expected,sizeof(a))!=sizeof(a)||RtlCompareMemory(&z,&expected,sizeof(z))!=sizeof(z)){st=STATUS_DEVICE_CONFIGURATION_ERROR;goto out;}
 PUCHAR base=p->Map[0];const ULONG off[]={0x1000,0x1800,0x20000,0x20004,0x20010,0x20030,0x20038,0x2003c};const ULONG val[]={0x1f300,1,0xc00067,0x32b,0x38071,0x803519,0xf404ff44,0xefe4};
 for(unsigned i=0;i<RTL_NUMBER_OF(off);i++)if(READ_REGISTER_ULONG((PULONG)(base+off[i]))!=val[i]){st=STATUS_DEVICE_DATA_ERROR;goto out;}
 if(READ_REGISTER_ULONG64((PULONGLONG)(base+0x20020))!=p->GpuUser.Root||READ_REGISTER_ULONG64((PULONGLONG)(base+0x20028))!=0||READ_REGISTER_ULONG((PULONG)(base+0x20058))!=0x400u){st=STATUS_DEVICE_DATA_ERROR;goto out;}
 p->GpuUser.After=expected;p->GpuUser.Active=1;p->GpuUser.Programming=0;tables->ActivationQualified=TRUE;st=STATUS_SUCCESS;
out:if(st!=STATUS_SUCCESS)p->GpuUser.Retained=1;BrokerUnlock(p);return st;
}
