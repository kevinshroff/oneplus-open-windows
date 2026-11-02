/* Explicit kernel API models. MMIO and Windows execution are not native. */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>
typedef uint32_t ULONG;typedef uint64_t ULONGLONG;
typedef int32_t LONG,NTSTATUS;typedef int64_t LONG64;
typedef pthread_mutex_t KMUTEX;typedef struct{int64_t QuadPart;}LARGE_INTEGER;
#define PASSIVE_LEVEL 0
#define Executive 0
#define KernelMode 0
#define FALSE 0
#define STATUS_SUCCESS 0
#define STATUS_TIMEOUT 258
#define RtlZeroMemory(p,n) memset(p,0,n)
static unsigned ForceTimeout,Irql;
static LONG InterlockedCompareExchange(volatile LONG*p,LONG v,LONG c){__atomic_compare_exchange_n(p,&c,v,0,__ATOMIC_SEQ_CST,__ATOMIC_SEQ_CST);return c;}
static LONG64 InterlockedCompareExchange64(volatile LONG64*p,LONG64 v,LONG64 c){__atomic_compare_exchange_n(p,&c,v,0,__ATOMIC_SEQ_CST,__ATOMIC_SEQ_CST);return c;}
static LONG InterlockedExchange(volatile LONG*p,LONG v){return __atomic_exchange_n(p,v,__ATOMIC_SEQ_CST);}
static LONG InterlockedIncrement(volatile LONG*p){return __atomic_add_fetch(p,1,__ATOMIC_SEQ_CST);}
static LONG InterlockedDecrement(volatile LONG*p){return __atomic_sub_fetch(p,1,__ATOMIC_SEQ_CST);}
static LONG64 InterlockedIncrement64(volatile LONG64*p){return __atomic_add_fetch(p,1,__ATOMIC_SEQ_CST);}
static unsigned KeGetCurrentIrql(void){return Irql;}
static void KeInitializeMutex(KMUTEX*m,unsigned l){assert(!l&&!pthread_mutex_init(m,NULL));}
static NTSTATUS KeWaitForSingleObject(KMUTEX*m,unsigned r,unsigned mode,unsigned alert,LARGE_INTEGER*t){
 assert(!r&&!mode&&!alert&&t->QuadPart==-10000);
 if(ForceTimeout)return STATUS_TIMEOUT;
 int n=pthread_mutex_trylock(m);if(!n)return STATUS_SUCCESS;assert(n==EBUSY);
 struct timespec ts={0,1000000};nanosleep(&ts,NULL);return STATUS_TIMEOUT;
}
static void KeReleaseMutex(KMUTEX*m,unsigned wait){assert(!wait&&!pthread_mutex_unlock(m));}
