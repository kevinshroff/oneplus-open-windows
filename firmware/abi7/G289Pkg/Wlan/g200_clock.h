/* SPDX-License-Identifier: MIT
 * G200 source candidate. No platform entrypoint or ACPI publisher; hardware
 * I/O is confined to the separately supplied bounded GCC backend.
 * Clock callbacks bind the audited EFI_CLOCK_PROTOCOL in g200_uefi_bind.c.
 */
#ifndef G200_CLOCK_H
#define G200_CLOCK_H
#include <stddef.h>
#include <stdint.h>
#define G200_EFI_ERROR(N) (UINT64_C(0x8000000000000000)|(N))
#define G200_INVALID G200_EFI_ERROR(2)
#define G200_UNSUPPORTED G200_EFI_ERROR(3)
#define G200_NOT_READY G200_EFI_ERROR(6)
#define G200_DEVICE_ERROR G200_EFI_ERROR(7)
#define G200_ABORTED G200_EFI_ERROR(21)
#define G200_OK UINT64_C(0)
#define G200_RESOURCE_COUNT 12U
#define G200_PREPIPE_STEPS 11U
enum G200_RESOURCE {G200_CORE,G200_PHY,G200_TCSR,G200_AUX,G200_CFG,G200_MSTR,
 G200_SLV,G200_SLV_Q2A,G200_RATE,G200_DDR,G200_AGGRE,G200_PIPE};
/* Explicit native receipts, all bound to the same exclusive lease/boot epoch.
 * These flags do NOT manufacture witnesses; the platform provider must earn
 * each before calling this source adapter. No such provider is shipped here.
 */
#define G200_W_COLD_SELECTED   (UINT64_C(1)<<0)
#define G200_W_PARENT_CX_MX    (UINT64_C(1)<<1)
#define G200_W_RADIO_SIX_RAILS (UINT64_C(1)<<2)
#define G200_W_ROOT_RAILS      (UINT64_C(1)<<3)
#define G200_W_AOP_PDC         (UINT64_C(1)<<4)
#define G200_W_REFERENCE       (UINT64_C(1)<<5)
#define G200_W_INTERCONNECT    (UINT64_C(1)<<6)
#define G200_W_PERST_ASSERTED  (UINT64_C(1)<<7)
#define G200_W_PIPE_MUX        (UINT64_C(1)<<8)
#define G200_W_RESETS_CYCLED   (UINT64_C(1)<<9)
#define G200_W_WLAN_EN         (UINT64_C(1)<<10)
#define G200_W_PHY_PROGRAMMED  (UINT64_C(1)<<11)
#define G200_W_NO_MAPPINGS     (UINT64_C(1)<<12)
#define G200_W_NO_PCI_CONSUMER (UINT64_C(1)<<13)
#define G200_W_AWAKE_PINNED    (UINT64_C(1)<<14)
#define G200_W_PERST_RELEASED (UINT64_C(1)<<15)
#define G200_POWER_PDC 0u
#define G200_POWER_AWAKE_PINNED 1u
#define G200_BEFORE_POWER (G200_W_COLD_SELECTED|G200_W_PARENT_CX_MX|G200_W_RADIO_SIX_RAILS|G200_W_ROOT_RAILS|G200_W_AOP_PDC|G200_W_REFERENCE|G200_W_INTERCONNECT|G200_W_PERST_ASSERTED|G200_W_WLAN_EN|G200_W_NO_PCI_CONSUMER)
#define G200_BEFORE_ACCESS (G200_BEFORE_POWER|G200_W_PIPE_MUX|G200_W_RESETS_CYCLED)
typedef uint64_t G200_STATUS;
typedef struct {
 void *This;
 uint64_t Version;
 G200_STATUS (*GetId)(void*,const char*,uintptr_t*);
 G200_STATUS (*Enable)(void*,uintptr_t);
 G200_STATUS (*Disable)(void*,uintptr_t);
 G200_STATUS (*IsEnabled)(void*,uintptr_t,uint8_t*);
 G200_STATUS (*IsOn)(void*,uintptr_t,uint8_t*);
 G200_STATUS (*SetHz)(void*,uintptr_t,uint32_t,uint32_t,uint32_t*);
 G200_STATUS (*GetHz)(void*,uintptr_t,uint32_t*);
 G200_STATUS (*GetDomainId)(void*,const char*,uintptr_t*);
 G200_STATUS (*EnableDomain)(void*,uintptr_t);
 G200_STATUS (*DisableDomain)(void*,uintptr_t);
 G200_STATUS (*RateTupleHz)(void*,uintptr_t,uint32_t[2][10],uint32_t*);
} G200_CLOCK_API;
typedef struct {
 uint64_t BootEpoch,OwnerEpoch,NowUs,ExpiresUs,Witnesses;
 uint8_t BootServicesActive,Exclusive,BackendIdentityPinned,PowerProfile;
} G200_LEASE;
/* G347 selected awake-only admission. The PDC profile remains exact. Only
 * this named alternative may substitute retained-active policy for the PDC
 * prerequisite, and it MUST NOT assert the unearned AOP_PDC witness.
 * Neither profile attests Windows/runtime sleep or post-EBS power lifetime.
 */
static inline int G200LeaseHas(const G200_LEASE*L,uint64_t Need){
 if(!L)return 0;
 if(L->PowerProfile==G200_POWER_AWAKE_PINNED){
  if(!(L->Witnesses&G200_W_AWAKE_PINNED)||(L->Witnesses&G200_W_AOP_PDC))return 0;
  if(Need&G200_W_AOP_PDC)Need=(Need&~G200_W_AOP_PDC)|G200_W_AWAKE_PINNED;
 }else if(L->PowerProfile!=G200_POWER_PDC)return 0;
 return (L->Witnesses&Need)==Need;
}
typedef struct {
 uintptr_t Id;
 uint32_t OriginalHz;
 uint8_t PriorOn,PriorEnabled,Acquired,RateChanged,HardwareRate,RateHandover;
} G200_CLOCK_RECORD;
typedef struct {
 uint32_t Attempted,Phase,Polls,On,Enabled,IssueOn,IssueEnabled,Mux,Vote,Cbcr;
 uint32_t SwReset,Start,PhyStatus,RawStable;
 G200_STATUS EnableStatus,OnStatus,EnabledStatus,LastStatus;
} G200_PIPE_TRACE;
_Static_assert(sizeof(G200_PIPE_TRACE)==88,"G396 PIPE trace");
typedef struct {
 G200_CLOCK_API Api;
 G200_LEASE Lease;
 G200_CLOCK_RECORD R[G200_RESOURCE_COUNT];
 uint32_t Next,Fault,UncertainMask,Open;
 uint32_t MuxTouched,MuxExternalKnown,ResetsCycled;
 G200_STATUS FirstStatus;
 uint32_t DiscoverIndex,DiscoverOp,DiscoverHz,DiscoverEnabled;
 G200_STATUS DiscoverStatus;
 uint32_t DiscoverOn,HardwareRateAdmitted,RateWords[2][10],InitialRateWords[10];
 G200_STATUS RateStatus;
 G200_PIPE_TRACE Pipe;
} G200_CLOCK_CONTEXT;
typedef struct {
 void *Opaque;
 G200_STATUS (*Read32)(void*,uint64_t,uint32_t*);
 G200_STATUS (*Write32)(void*,uint64_t,uint32_t);
 G200_STATUS (*StallUs)(void*,uint32_t);
} G200_GCC_IO;
G200_STATUS G200PipeStart(G200_CLOCK_CONTEXT*,const G200_LEASE*,const G200_GCC_IO*);
G200_STATUS G200PipePoll(G200_CLOCK_CONTEXT*,const G200_LEASE*,const G200_GCC_IO*,uint32_t,uint8_t);
G200_STATUS G200GccMuxExternal(G200_CLOCK_CONTEXT*,const G200_LEASE*,const G200_GCC_IO*);
G200_STATUS G200GccResetPair(G200_CLOCK_CONTEXT*,const G200_LEASE*,const G200_GCC_IO*);
G200_STATUS G200GccMuxXo(G200_CLOCK_CONTEXT*,const G200_LEASE*,const G200_GCC_IO*);
typedef struct {const char *Name;uint32_t Hz;uint8_t Domain;} G200_RESOURCE_SPEC;
G200_STATUS G200ValidateRateTuple(const uint32_t[2][10],uint32_t*);
extern const G200_RESOURCE_SPEC G200Resources[G200_RESOURCE_COUNT];
G200_STATUS G200ClockOpen(G200_CLOCK_CONTEXT*,const G200_CLOCK_API*,const G200_LEASE*);
G200_STATUS G200ClockNext(G200_CLOCK_CONTEXT*,const G200_LEASE*);
G200_STATUS G200ClockRetire(G200_CLOCK_CONTEXT*,const G200_LEASE*);
/* Exact G125 ordered GCC/TLMM words, supplied by a separately admitted reader.
 * This function performs no reads. It cannot admit a historical capture.
 */
G200_STATUS G200PassiveReady(const uint32_t Samples[2][24]);
G200_STATUS G200ActiveReady(G200_CLOCK_CONTEXT*,const G200_LEASE*,const uint32_t[2][24]);
G200_STATUS G200AccessReady(G200_CLOCK_CONTEXT*,const G200_LEASE*,const uint32_t Samples[2][24],uint8_t RequirePipe);
#endif
