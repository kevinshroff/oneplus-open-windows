/* Included only by the real owner, after FirstUseFrame. No new mapper or
 * programming authority: this separate guard admits fixed READS while GX is
 * on. gpu_cp_translate.c::Current and all write guards remain unchanged. */
static int G1325Current(void*x){
 OGO_CONTEXT*p=x;G982_CP*c=p?p->Cp:NULL;
 if(!c||KeGetCurrentIrql()!=PASSIVE_LEVEL||!c->WitnessAttempted||c->Phase!=4||
    !c->Run.RunAttempted||!c->Run.Core.attempted||c->Run.Core.stage!=3||!c->Run.Power.attempted||
    !c->Published||!c->Smmu||!p->Active||c->Smmu!=p->Active->Native.Base||
    p->Active->Native.Io.register_bytes!=0x40000||!c->SqeInput)return -1;
 return FirstUseFrame(p)!=STATUS_SUCCESS;
}
static int G1325Read(void*x,ULONG off,ULONG width,ULONGLONG*out){
 OGO_CONTEXT*p=x;G1325_ITEM plan[25];BOOLEAN allowed=FALSE;
 G1325Plan(plan,p->Cp->Tables.Tables.root_physical,p->Cp->After.Smr[1],p->Cp->After.S2cr[1],p->Cp->After.Nscr0,p->Cp->After.Nsacr);
 for(ULONG i=0;i<25;i++)if(off==plan[i].Offset&&width==plan[i].Width)allowed=TRUE;
 if(!out||!allowed||G1325Current(p))return -1;
 *out=width==8?READ_REGISTER_ULONG64((PULONGLONG)((PUCHAR)p->Cp->Smmu+off)):
               READ_REGISTER_ULONG((PULONG)((PUCHAR)p->Cp->Smmu+off));return 0;
}
static int G1325Backing(void*x,ULONG*checked,ULONG*mismatch){
 OGO_CONTEXT*p=x;G321_BUFFER*b=&p->Cp->Run.Buffer[2];
 if(!checked||!mismatch||G1325Current(p)||!b->Mdl||!b->Cpu||
    !(b->Mdl->MdlFlags&MDL_PAGES_LOCKED)||MmGetMdlByteOffset(b->Mdl)||
    MmGetMdlByteCount(b->Mdl)!=0x13000||p->Cp->Run.Layout.Bytes[2]!=0x13000||
    G433_SQE_FILE_BYTES<4||G433_SQE_FILE_BYTES>0x13000)return -1;
 *checked=0;*mismatch=0;
 for(SIZE_T page=0;page<0x13000;page+=4096){
  if(G1325Current(p))return -1;
  if((ULONGLONG)MmGetPhysicalAddress((PUCHAR)b->Cpu+page).QuadPart!=
     (ULONGLONG)MmGetMdlPfnArray(b->Mdl)[page/4096]*4096)return -1;
  for(SIZE_T j=page;j<page+4096;j++){
   UCHAR want=j<G433_SQE_FILE_BYTES-4?p->Cp->SqeInput[j+4]:0;
   if(((volatile UCHAR*)b->Cpu)[j]!=want){if(!*mismatch)*mismatch=(ULONG)j+1;}
   (*checked)++;
  }
 }
 return G1325Current(p);
}
static NTSTATUS G1325StopBeforeRelease(OGO_CONTEXT*p){
 G982_CP*c=p->Cp;G1325_REPORT r;G1325_ITEM plan[25];ULONG gx=0,ahb=0;
 /* Once consumed even on failed admission; existing retention is sticky. */
 if(c->WitnessAttempted)return STATUS_INVALID_DEVICE_STATE;
 c->WitnessAttempted=TRUE;c->Retain=TRUE;RtlZeroMemory(&r,sizeof(r));
 G1325Plan(plan,c->Tables.Tables.root_physical,c->After.Smr[1],c->After.S2cr[1],c->After.Nscr0,c->After.Nsacr);
 /* Existing GX-on and AHB-clear source checks precede new SMMU/backing reads.
  * A failed current/power check admits no witness readback. */
 int result=-1;
 if(!G1325Current(p)&&G482CoreRead(&p->Io,0x14340,&gx)==STATUS_SUCCESS&&!(gx&3)&&gx!=MAXULONG&&
    !G1325Current(p)&&G482CoreRead(&p->Io,0x24c4c,&ahb)==STATUS_SUCCESS&&!ahb){
  G1325_OPS ops={p,G1325Current,G1325Read,G1325Backing};result=G1325Collect(&ops,plan,&r);
 }
 for(ULONG pass=0;pass<2;pass++)for(ULONG i=0;i<25;i++)if(r.Valid[pass]&(1u<<i))
  LogPrint("G1325 witness run%llx pass%u off%x width%u raw%llx\n",p->RunId,pass,plan[i].Offset,plan[i].Width,r.Value[pass][i]);
 LogPrint("G1325 STOP_BEFORE_RELEASE run%llx result%d gx%x ahb%x valid%x/%x mismatch%x unstable%x fault%x backing%u firstMismatchPlus1%x retain1 start0 translationProof0\n",p->RunId,result,gx,ahb,r.Valid[0],r.Valid[1],r.Mismatch,r.Unstable,r.Fault,r.BackingChecked,r.BackingMismatch);
 /* A clean witness is an intentional refusal, never a successful CP start. */
 return result?STATUS_DEVICE_DATA_ERROR:STATUS_NOT_SUPPORTED;
}
