/* Fixed-purpose broker ABI7. Included after gpu_user_native.inc. */
#if OPEN_QTB_WITNESS
typedef struct {
 OSM_CONTEXT *P;OLB_NATIVE *B;OGU_TOKEN *User;const OPEN_NS_SCOPE *Scope;
 OSMI_TABLES *Tables;PMDL Mdl;PETHREAD Thread;PVOID Tag,Map,SmmuMap;
 ULONGLONG Generation,Token,ClockToken,Root,Iova,Pa,UserId;PVOID Pool;OSMA_NATIVE_IO*RunNative;ULONG Sctlr,GmuRefs,LeaseRefs,Clients,RawFsr,RawGlobal,RawCb2;
 BOOLEAN MaskAttempted,NormalAcquired;
 struct qtb_report Report;
}QTB_NATIVE;
/* No normal Frame(), FaultCheck() or Current() here: ISR poison cannot revoke
 * ONLY our original-register restoration while immutable authority survives.
 * STOP/surprise removal, map/token/ref identity loss DO revoke access. */
static int QtbCleanup(void*x){QTB_NATIVE*q=x;OSM_CONTEXT*p=q->P;CGH_NATIVE*h=q->B->Hold;
 return KeGetCurrentIrql()!=PASSIVE_LEVEL||PsGetCurrentThread()!=q->Thread||!p->Started||p->Removing||p->StopPending||p->RemovePending||!p->D0Ref||p->Qtb!=q||p->QtbMap!=q->Map||p->Map[0]!=q->SmmuMap||!p->QtbGranted||p->Generation!=q->Generation||p->NsGeneration!=q->Generation||p->NsThread!=q->Thread||p->NsTag!=q->Tag||p->NsToken!=q->Token||p->NsBank!=q->B||p->GpuUserTag!=q->User||p->GpuUserGmu!=q->B||p->GpuTables!=q->Tables||!q->B->Referenced||q->B->Fdo!=p->Fdo||!q->User->Referenced||q->Tables->PoolOrigin!=0x4e435047u||q->Tables->Tables.root_physical!=q->Root||q->Tables->Pool!=q->Pool||p->RunNative!=q->RunNative||!p->RunNative||p->RunNative->Tables->References<2||p->GpuUser.Id!=q->UserId||q->User->Id!=q->UserId||q->User->Generation!=q->Generation||q->B->Generation!=q->Generation||!q->Tables->Pool||!q->Mdl||!(q->Mdl->MdlFlags&MDL_PAGES_LOCKED)||MmGetMdlByteOffset(q->Mdl)||!h||h->Clock.Token!=q->ClockToken||h->Clock.Api.Interface.Context!=p||!p->GmuClients||p->Gmu.refs!=q->GmuRefs||p->Gmu.refs!=p->GmuClients||p->Gmu.generation!=q->Generation||p->Lease.generation!=q->Generation||p->Lease.refs!=q->LeaseRefs||p->Clients!=q->Clients||!p->Clients;
}
static int QtbCurrent(void*x){QTB_NATIVE*q=x;OSM_CONTEXT*p=q->P;
 if(QtbCleanup(x)||p->Faulted||InterlockedCompareExchange(&p->NsRevoked,0,0)||InterlockedCompareExchange(&p->Fault.Journal.Fatal,0,0)||p->Fault.Retain||!GpuScope(p,q->B,q->Scope)||q->Tables->State!=OSMI_BUILT||!q->Tables->ActivationQualified||p->Gmu.state!=GMC_HELD||p->Lease.state!=OSM_ACTIVE)return -1;
 ULONG ctl=READ_REGISTER_ULONG((PULONG)((PUCHAR)q->SmmuMap+0x20000));KeMemoryBarrier();return ctl!=(q->MaskAttempted?(q->Sctlr&~0xc0u):q->Sctlr);
}
static int QtbAcquire(void*x,uint64_t*i,uint64_t*a){QTB_NATIVE*q=x;if(q->NormalAcquired||QtbCurrent(q))return -1;q->NormalAcquired=TRUE;*i=q->Iova;*a=q->Pa;return 0;}
static int QtbRead64(void*x,unsigned off,uint64_t*v){QTB_NATIVE*q=x;
 if(!v||QtbCleanup(q))return -1;
 if(off!=Q_REQ&&off!=Q_ACK&&off!=Q_TRIGGER&&off!=Q_STATUS&&off!=Q_OUT)return -1;
 *v=READ_REGISTER_ULONG64((PULONGLONG)((PUCHAR)q->Map+off));KeMemoryBarrier();return *v==MAXULONGLONG?-1:0;
}
static int QtbWrite64(void*x,unsigned off,uint64_t v){QTB_NATIVE*q=x;BOOLEAN restoration=FALSE;
 if(off==Q_REQ){if(v==q->Report.req_before)restoration=TRUE;else if(v!=(q->Report.req_before|1))return -1;}
 else if(off==Q_TRIGGER){if(!v)restoration=TRUE;else if(v!=1)return -1;}
 else if(off==Q_IN0){if(v)return -1;}else if(off==Q_IN1){if(v!=0x3408)return -1;}else if(off==Q_IN2){if(v!=q->Iova)return -1;}else return -1;
 if(restoration?QtbCleanup(q):QtbCurrent(q))return -1;
 WRITE_REGISTER_ULONG64((PULONGLONG)((PUCHAR)q->Map+off),v);KeMemoryBarrier();return 0;
}
static int QtbSctlrRead(void*x,uint32_t*v){QTB_NATIVE*q=x;if(!v||QtbCleanup(q))return -1;*v=READ_REGISTER_ULONG((PULONG)((PUCHAR)q->SmmuMap+0x20000));KeMemoryBarrier();return *v==MAXULONG?-1:0;}
static int QtbSctlrWrite(void*x,uint32_t v){QTB_NATIVE*q=x;
 if(v==q->Sctlr){if(QtbCleanup(q))return -1;}
 else {if(v!=(q->Sctlr&~0xc0u)||QtbCurrent(q))return -1;q->MaskAttempted=TRUE;}
 WRITE_REGISTER_ULONG((PULONG)((PUCHAR)q->SmmuMap+0x20000),v);KeMemoryBarrier();return 0;
}
static int QtbFaults(void*x,uint32_t*f,uint64_t*a,uint32_t*s,uint32_t*other){QTB_NATIVE*q=x;PUCHAR b=q->SmmuMap;if(QtbCleanup(q))return -1;
 q->RawFsr=READ_REGISTER_ULONG((PULONG)(b+0x20058));*f=q->RawFsr&~0x400u;*a=READ_REGISTER_ULONG64((PULONGLONG)(b+0x20060));*s=READ_REGISTER_ULONG((PULONG)(b+0x20068));
 q->RawGlobal=READ_REGISTER_ULONG((PULONG)(b+0x48));q->RawCb2=READ_REGISTER_ULONG((PULONG)(b+0x22058));*other=(InterlockedCompareExchange(&q->P->Fault.Journal.Fatal,0,0)?1u:0u)|q->RawGlobal|(q->RawCb2&~0x400u);KeMemoryBarrier();return q->RawFsr==MAXULONG||q->RawGlobal==MAXULONG||q->RawCb2==MAXULONG?-1:0;
}
static int QtbSync(void*x){QTB_NATIVE*q=x;if(QtbCleanup(q))return -1;ULONG v=READ_REGISTER_ULONG((PULONG)q->Map);KeMemoryBarrier();return v==MAXULONG?-1:0;}
static uint64_t QtbNow(void*x){UNREFERENCED_PARAMETER(x);return KeQueryInterruptTimePrecise(NULL)/10;}
static void QtbFinish(void*x,int uncertain){QTB_NATIVE*q=x;if(uncertain){q->P->Faulted=TRUE;q->P->GpuUser.Retained=1;}/* no free/unmap/droprefs, even MATCH */}
/* Firmware OWQT is a pre-EBS receipt, not electrical-state attestation. Native
 * acceptance also requires the root's exact NEW firmware/table identity. */
static NTSTATUS QtbFirmwareVote(void){UCHAR a[80];ULONG got=0;NTSTATUS s=AuxKlibGetSystemFirmwareTable(0x41435049u,0x5451574fu,a,sizeof(a),&got);if(s!=STATUS_SUCCESS)return s;
 if(got!=sizeof(a))return STATUS_DEVICE_CONFIGURATION_ERROR;UCHAR sum=0;for(ULONG i=0;i<got;i++)sum+=a[i];ULONG n,v,m,d,t,f;ULONGLONG ib,ab,status;RtlCopyMemory(&n,a+4,4);RtlCopyMemory(&v,a+36,4);RtlCopyMemory(&m,a+40,4);RtlCopyMemory(&d,a+44,4);RtlCopyMemory(&t,a+48,4);RtlCopyMemory(&ib,a+52,8);RtlCopyMemory(&ab,a+60,8);RtlCopyMemory(&f,a+68,4);RtlCopyMemory(&status,a+72,8);if(sum||RtlCompareMemory(a,"OWQT",4)!=4||n!=80||v!=1||m!=196||d||t!=4||ib!=1000000||ab||f!=1||status)return STATUS_DEVICE_CONFIGURATION_ERROR;return STATUS_SUCCESS;
}
static NTSTATUS QtbOnceApi(PVOID x,OLB_NATIVE*b,OGU_TOKEN*t,const OPEN_NS_SCOPE*s,OSMI_TABLES*tables,PMDL mdl,ULONGLONG iova,struct qtb_report*out){OSM_CONTEXT*p=x;NTSTATUS st;
 if(!out||!mdl||!tables||p->Qtb||!p->QtbGranted||!p->QtbMap)return STATUS_INVALID_DEVICE_STATE;
 st=GpuUserCheckApi(p,b,t,s);if(st!=STATUS_SUCCESS)return st;st=QtbFirmwareVote();if(st!=STATUS_SUCCESS)return st;
 if(!tables->ActivationQualified||tables!=p->GpuTables||tables->State!=OSMI_BUILT||!tables->Ranges||tables->RangeCount>OSMI_MAX_LEAVES||!b->Hold||!b->Hold->BootCommitted||!b->Hold->Clock.Token||!(mdl->MdlFlags&MDL_PAGES_LOCKED)||MmGetMdlByteOffset(mdl)||MmGetMdlByteCount(mdl)!=0x13000||!iova||(iova&4095))return STATUS_INVALID_DEVICE_STATE;
 ULONGLONG pa=(ULONGLONG)MmGetMdlPfnArray(mdl)[0]<<PAGE_SHIFT;ULONG matches=0;
 for(SIZE_T n=0;n<tables->RangeCount;n++){ArmSmmu4KRange*r=&tables->Ranges[n];if(r->iova==iova&&r->physical==pa&&r->bytes==4096&&r->permissions==15&&r->writeback==0&&r->shareability==2)matches++;}if(matches!=1)return STATUS_DEVICE_DATA_ERROR;
 QTB_NATIVE*q=ExAllocatePool2(POOL_FLAG_NON_PAGED,sizeof(*q),TAG);if(!q)return STATUS_INSUFFICIENT_RESOURCES;RtlZeroMemory(q,sizeof(*q));
 st=IoAcquireRemoveLock(&p->Remove,q);if(st!=STATUS_SUCCESS){ExFreePoolWithTag(q,TAG);return st;}
 BrokerLock(p);
 if(p->Qtb||!GpuScope(p,b,s)||Frame(p,p->Generation)||p->NsThread!=PsGetCurrentThread()){BrokerUnlock(p);IoReleaseRemoveLock(&p->Remove,q);ExFreePoolWithTag(q,TAG);return STATUS_DEVICE_NOT_READY;}
 q->P=p;q->B=b;q->User=t;q->Scope=s;q->Tables=tables;q->Mdl=mdl;q->Thread=PsGetCurrentThread();q->Tag=p->NsTag;q->Generation=p->Generation;q->Token=p->NsToken;q->ClockToken=b->Hold->Clock.Token;q->Map=p->QtbMap;q->SmmuMap=p->Map[0];q->Root=tables->Tables.root_physical;q->Iova=iova;q->Pa=pa;q->Sctlr=OGO_GPU_CB0_SCTLR;q->UserId=p->GpuUser.Id;q->Pool=tables->Pool;q->RunNative=p->RunNative;q->GmuRefs=p->Gmu.refs;q->LeaseRefs=p->Lease.refs;q->Clients=p->Clients;p->Qtb=q;ObReferenceObject(p->Fdo);BrokerUnlock(p);
 struct qtb_io io={q,QtbAcquire,QtbCurrent,QtbCleanup,QtbRead64,QtbWrite64,QtbSctlrRead,QtbSctlrWrite,QtbFaults,QtbSync,QtbNow,QtbFinish};enum qtb_result result=qtb_once(&io,&q->Report);q->Report.raw_fsr=q->RawFsr;q->Report.raw_global_fsr=q->RawGlobal;q->Report.raw_cb2_fsr=q->RawCb2;*out=q->Report;
 DbgPrintEx(DPFLTR_IHVDRIVER_ID,DPFLTR_INFO_LEVEL,"QTB once result%u raw%llx extracted%llx expected%llx pfn%llx status%llx fsrFiltered%x fsrRaw%x globalRaw%x cb2Raw%x far%llx syn%x other%x restored%u uncertain%u; retain1 noSQErelease\n",result,out->out,out->extracted,out->expected_mdl_pa,out->expected_pfn,out->status,out->fsr,out->raw_fsr,out->raw_global_fsr,out->raw_cb2_fsr,out->far,out->syndrome,out->other_fault,out->cleanup_restored,out->uncertain);
 return result==QTB_MATCH&&out->cleanup_restored&&!out->uncertain?STATUS_SUCCESS:STATUS_DEVICE_HARDWARE_ERROR;
}
#endif
