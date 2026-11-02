/* SPDX-License-Identifier: MIT. Included ONCE inside the copied real MMU1
 * WDM owner. Uses its actual START/maps/D0/mutex/remove/ref/client lifetime. */
static int GmuCurrent(void*x,uint64_t g){OSM_CONTEXT*p=x;return !Frame(p,g)&&p->D0Ref&&!p->StopPending&&!p->RemovePending&&p->Lease.state==OSM_ACTIVE&&p->Lease.refs==p->Clients+1&&osm_witness(&p->Lease,g)==OSM_OK?0:-1;}
static BOOLEAN GmuReadAllowed(ULONGLONG a){static const ULONGLONG v[]={0x03d91000,0x03d91004,0x03d91010,0x03d91014,0x03d91018,0x03d9101c,0x03d99318,0x03d9931c,0x03d9913c,0x03d99144,0x00171154,0x00171010,0x03d9911c,0x03d99148,0x03d990bc};for(unsigned i=0;i<RTL_NUMBER_OF(v);i++)if(a==v[i])return TRUE;return FALSE;}
static int GmuRead(void*x,uint64_t a,uint32_t*out){OSM_CONTEXT*p=x;unsigned m;ULONG o;if(!out||GmuCurrent(x,p->Generation)||!GmuReadAllowed(a))return -1;for(m=0;m<OSM_MAPS;m++)if(a>=osm_required_ranges[m].pa&&a-osm_required_ranges[m].pa<=osm_required_ranges[m].bytes-4)break;if(m==OSM_MAPS||!p->Granted[m]||!p->Map[m])return -1;o=(ULONG)(a-osm_required_ranges[m].pa);*out=READ_REGISTER_ULONG((PULONG)((PUCHAR)p->Map[m]+o));return *out==MAXULONG?-1:0;}
static int GmuWrite(void*x,uint64_t a,uint32_t before,uint32_t desired){OSM_CONTEXT*p=x;uint32_t current;ULONG mask;unsigned m;static const ULONGLONG leaves[]={0x03d9913c,0x03d99144,0x00171154,0x00171010,0x03d9911c,0x03d99148};
 if(a==0x03d9911c||GmuCurrent(x,p->Generation)||GmuRead(x,a,&current))return -1; /* AHB stays with original four-clock aggregate owner. */
 if(a==0x03d99318)mask=3;else if(a==0x03d9931c)mask=0x0010371f;else{mask=0;for(unsigned i=0;i<RTL_NUMBER_OF(leaves);i++)if(a==leaves[i])mask=1;}
 if(((a==0x03d9913c||a==0x00171154)&&!(desired&1u))||!mask||((before^desired)&~mask)||((current^before)&(a==0x03d99318?0x7fffffffu:(mask==1?0x0fffffffu:MAXULONG))))return -1;
 for(m=0;m<OSM_MAPS;m++)if(a>=osm_required_ranges[m].pa&&a-osm_required_ranges[m].pa<=osm_required_ranges[m].bytes-4)break;
 if(m==OSM_MAPS||!osm_required_ranges[m].writable||!p->Granted[m]||!p->Map[m])return -1;
 ULONG v=(current&~mask)|(desired&mask);p->WritesAttempted++;p->LastWritePa=a;p->LastWriteBefore=current;p->LastWriteValue=v;WRITE_REGISTER_ULONG((PULONG)((PUCHAR)p->Map[m]+(ULONG)(a-osm_required_ranges[m].pa)),v);KeMemoryBarrier();return 0;
}
static VOID GmuBarrier(void*x){UNREFERENCED_PARAMETER(x);KeMemoryBarrier();}
static VOID GmuWait(void*x){UNREFERENCED_PARAMETER(x);KeStallExecutionProcessor(1);}
static GMC_IO GmuOps(OSM_CONTEXT*p){GMC_IO o={p,p->Generation,GmuCurrent,GmuRead,GmuWrite,GmuBarrier,GmuWait};return o;}
static NTSTATUS GmuStatus(enum gmc_error e){return e==GMC_OK?STATUS_SUCCESS:e==GMC_NEED_PLL_OWNER?STATUS_NOT_SUPPORTED:e==GMC_TIMEOUT?STATUS_IO_TIMEOUT:STATUS_DEVICE_HARDWARE_ERROR;}
static NTSTATUS GmuAcquireApi(PVOID context,const OPEN_CLOCK_CLIENT*c,ULONGLONG*out){
 OSM_CONTEXT*p=context;if(!out||!c||KeGetCurrentIrql()!=PASSIVE_LEVEL)return STATUS_INVALID_PARAMETER;*out=0;
 if(c->Size!=sizeof(*c)||c->Version!=OPEN_CLOCK_VERSION||c->Role!=OPEN_CLOCK_GPU_CLIENT||c->Reserved||!c->Context||!c->Generation||!c->Pdo||!c->Current||!c->Drained||!OpenExactHardwareId(c->Pdo,L"ACPI\\OPEN0515"))return STATUS_ACCESS_DENIED;
 BrokerLock(p);NTSTATUS st=STATUS_DEVICE_NOT_READY;unsigned slot=RTL_NUMBER_OF(p->GmuSlots);
 if(!GmuCurrent(p,p->Generation)&&p->TokenSequence!=MAXULONGLONG&&ClientCurrent(c)){
  for(unsigned i=0;i<RTL_NUMBER_OF(p->GmuSlots);i++)if(!p->GmuSlots[i].Id){slot=i;break;}
  if(slot==RTL_NUMBER_OF(p->GmuSlots))st=STATUS_INSUFFICIENT_RESOURCES;
  else{GMC_IO io=GmuOps(p);st=GmuStatus(GmcAcquire(&p->Gmu,&io));if(st==STATUS_SUCCESS){struct osm_ops o=Ops(p);st=CoreStatus(osm_acquire(&p->Lease,&o,p->Generation));if(st==STATUS_SUCCESS){OSM_CLIENT_SLOT*t=&p->GmuSlots[slot];t->Client=*c;ObReferenceObject(c->Pdo);t->Id=++p->TokenSequence;p->Clients++;p->GmuClients++;*out=t->Id;}else p->Faulted=TRUE;}else if(p->Gmu.attempted)p->Faulted=TRUE;}
 }BrokerUnlock(p);return st;
}
static NTSTATUS GmuWitnessApi(PVOID context,ULONGLONG token,OPEN_GMU_CLOCK_SNAPSHOT*out){OSM_CONTEXT*p=context;if(!token||!out||KeGetCurrentIrql()!=PASSIVE_LEVEL)return STATUS_INVALID_PARAMETER;RtlZeroMemory(out,sizeof(*out));BOOLEAN already=p->LockThread==KeGetCurrentThread();if(!already)BrokerLock(p);NTSTATUS st=STATUS_INVALID_DEVICE_STATE;
 if(!GmuCurrent(p,p->Generation)&&p->Gmu.refs==p->GmuClients){for(unsigned i=0;i<RTL_NUMBER_OF(p->GmuSlots);i++)if(p->GmuSlots[i].Id==token&&ClientCurrent(&p->GmuSlots[i].Client)){st=CoreStatus(osm_witness(&p->Lease,p->Generation));if(st==STATUS_SUCCESS)st=GmuStatus(GmcWitness(&p->Gmu));if(st==STATUS_SUCCESS){out->Size=sizeof(*out);out->Version=1;RtlCopyMemory(out->Branches,p->Gmu.raw,sizeof(out->Branches));out->OwnedMask=p->Gmu.owned_mask;out->DelayRequestMask=p->Gmu.delay_request_mask;out->Bit0ConfirmedMask=p->Gmu.bit0_confirmed_mask;out->RootCfg=p->Gmu.root_expected;out->Generation=p->Generation;}else p->Faulted=TRUE;break;}}
 if(!already)BrokerUnlock(p);return st;
}
static NTSTATUS GmuReleaseApi(PVOID context,ULONGLONG token){OSM_CONTEXT*p=context;if(!token||KeGetCurrentIrql()!=PASSIVE_LEVEL)return STATUS_INVALID_PARAMETER;BrokerLock(p);NTSTATUS st=STATUS_INVALID_DEVICE_STATE;if(p->BankClaims){BrokerUnlock(p);return STATUS_DEVICE_BUSY;}
 if(!p->BankClaims&&!GmuCurrent(p,p->Generation)&&p->GmuClients&&p->Gmu.refs==p->GmuClients){for(unsigned i=0;i<RTL_NUMBER_OF(p->GmuSlots);i++){OSM_CLIENT_SLOT*t=&p->GmuSlots[i];if(t->Id!=token)continue;if(!ClientCurrent(&t->Client)||t->Client.Drained(t->Client.Context,t->Client.Pdo,t->Client.Generation)!=STATUS_SUCCESS){st=STATUS_DEVICE_BUSY;break;}
  st=GmuStatus(GmcReleaseCold(&p->Gmu));if(st==STATUS_SUCCESS)st=CoreStatus(osm_release(&p->Lease,p->Generation));if(st==STATUS_SUCCESS){DbgPrintEx(DPFLTR_IHVDRIVER_ID,DPFLTR_INFO_LEVEL,"OpenGmuClock release requestDropped%x writeCleared%x aonLeftEnabled%x rootLeftConfigured%u; not physical-stop/no DMA proof\n",p->Gmu.request_dropped_mask,p->Gmu.write_cleared_mask,p->Gmu.no_disable_left_mask,p->Gmu.root_left_configured);ObDereferenceObject(t->Client.Pdo);RtlZeroMemory(t,sizeof(*t));p->Clients--;p->GmuClients--;}else p->Faulted=TRUE;break;}}
 BrokerUnlock(p);return st;
}
