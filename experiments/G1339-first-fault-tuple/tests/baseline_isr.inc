/* Frozen pre-G1339 ISR for default-off preprocessing parity only. */
static BOOLEAN FaultIsr(PKINTERRUPT irq,PVOID context){UNREFERENCED_PARAMETER(irq);OF_ISR_CONTEXT*c=context;OF_OWNER*f=c->Owner;if(!InterlockedCompareExchange(&f->Armed,0,0))return FALSE;
 ULONG off=c->Index?0x58:0x48;ULONG v=READ_REGISTER_ULONG((PULONG)((PUCHAR)f->Map[c->Index]+off));ULONG ack=OfAckPolicy(&f->Journal,c->Index,v);
 if(ack){WRITE_REGISTER_ULONG((PULONG)((PUCHAR)f->Map[c->Index]+off),ack);KeMemoryBarrier();}return (c->Index?(v&~0x400u):v)?TRUE:FALSE;
}
