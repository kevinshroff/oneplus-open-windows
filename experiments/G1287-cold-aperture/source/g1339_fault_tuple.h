/* Private first-fault journal, no external interface layout or ACK policy.
 * Caller owns interrupt serialization/mapping lifetime. No decode/translation
 * claim: FAR halves and syndrome words are preserved exactly as read. */
#ifndef G1339_FAULT_TUPLE_H
#define G1339_FAULT_TUPLE_H
#if defined(_KERNEL_MODE)
typedef ULONGLONG OF_U64;
#else
typedef uint64_t OF_U64;
#endif
typedef struct {
 volatile OF_LONG State; /* 0 empty, 1 claimed/incomplete, 2 published. */
 OF_U64 Generation;
 OF_WORD Index,Status,ReadMask,AllOnesMask,Refused;
 OF_WORD FarLo,FarHi,Fsynr0,Fsynr1,Gfsynr0,Gfsynr1,Gfsynr2;
} OF_FIRST_FAULT;
typedef OF_WORD (*OF_TUPLE_READ)(void*,unsigned,unsigned);
static inline int OfTupleClaim(volatile OF_LONG*p){
#if defined(_KERNEL_MODE)
 return InterlockedCompareExchange(p,1,0)==0;
#else
 OF_LONG expected=0;return __atomic_compare_exchange_n(p,&expected,1,0,__ATOMIC_SEQ_CST,__ATOMIC_SEQ_CST);
#endif
}
static inline void OfTuplePublish(volatile OF_LONG*p){
#if defined(_KERNEL_MODE)
 InterlockedExchange(p,2);
#else
 __atomic_store_n(p,2,__ATOMIC_SEQ_CST);
#endif
}
/* These have no clear/ACK semantics. Arm IHI0062D: CB_FAR[63:0]
 * +60/+64, FSYNR0/1 +68/+6c; GR0 GFSYNR0/1/2 +50/+54/+58.
 * Region0 is already-owned GR0; region2 is already-owned CB0, not CB2. */
static inline OF_WORD OfTupleRead(OF_FIRST_FAULT*t,OF_TUPLE_READ read,void*x,
 unsigned region,unsigned off,unsigned bit){
 OF_WORD v=read(x,region,off);t->ReadMask|=1u<<bit;
 if(v==OF_ALLONES)t->AllOnesMask|=1u<<bit;return v;
}
static inline int OfFirstFaultCapture(OF_FIRST_FAULT*t,OF_U64 generation,
 OF_WORD index,OF_WORD status,int global_current,int cb0_current,
 OF_TUPLE_READ read,void*x){
 if(index>2||!status||(index&&status==0x400u))return 0;
 /* Kernel interlocked operations publish fields only after all readbacks.
  * Tests supply equivalent atomic intrinsics; no spinning/retry in ISR. */
 if(!OfTupleClaim(&t->State))return 0;
 t->Index=index;t->Status=status;
 if(t->Generation!=generation)t->Refused|=1u;
 if(!global_current)t->Refused|=2u;
 if(status==OF_ALLONES)t->Refused|=4u;
 if(!t->Refused){
  if(index==2&&cb0_current){
   t->FarLo=OfTupleRead(t,read,x,2,0x60,0);
   t->FarHi=OfTupleRead(t,read,x,2,0x64,1);
   t->Fsynr0=OfTupleRead(t,read,x,2,0x68,2);
   t->Fsynr1=OfTupleRead(t,read,x,2,0x6c,3);
  }else if(index==2)t->Refused|=8u;
  t->Gfsynr0=OfTupleRead(t,read,x,0,0x50,4);
  t->Gfsynr1=OfTupleRead(t,read,x,0,0x54,5);
  t->Gfsynr2=OfTupleRead(t,read,x,0,0x58,6);
 }
 OfTuplePublish(&t->State);return 1;
}
#endif
