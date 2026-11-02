#include "ntddk.h"
#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
static _Thread_local unsigned Irql,Depth;
static _Atomic uint64_t InterruptTime;
unsigned KeGetCurrentIrql(void) { return Irql; }
uint64_t KeQueryInterruptTime(void) { return atomic_load(&InterruptTime); }
void MockSetTimeUs(uint64_t us) { assert(us<=UINT64_MAX/10);atomic_store(&InterruptTime,us*10); }
void MockSetIrql(unsigned irql) { assert(!Depth);Irql=irql; }
unsigned MockLockDepth(void) { return Depth; }
void ExInitializeFastMutex(FAST_MUTEX *p) {
 assert(!Irql&&!Depth);pthread_mutex_t *m=malloc(sizeof(*m));assert(m);
 assert(!pthread_mutex_init(m,0));memset(p,0,sizeof(*p));p->Opaque[0]=(uintptr_t)m;
}
void ExAcquireFastMutex(FAST_MUTEX *p) {
 assert(!Irql&&!Depth);assert(!pthread_mutex_lock((pthread_mutex_t*)p->Opaque[0]));Irql=APC_LEVEL;Depth=1;
}
void ExReleaseFastMutex(FAST_MUTEX *p) {
 assert(Irql==APC_LEVEL&&Depth==1);Depth=0;Irql=PASSIVE_LEVEL;
 assert(!pthread_mutex_unlock((pthread_mutex_t*)p->Opaque[0]));
}
void MockDestroyMutex(FAST_MUTEX *p) {
 assert(!Irql&&!Depth);assert(!pthread_mutex_destroy((pthread_mutex_t*)p->Opaque[0]));
 free((void*)p->Opaque[0]);p->Opaque[0]=0;
}
