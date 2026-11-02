/* One fixed cover clear in AfterReadyToBoot; later observers never clear. */
#ifndef G201_HANDOFF_H
#define G201_HANDOFF_H
#ifdef G201_HOST
#include <stdint.h>
#include <stddef.h>
typedef uint8_t UINT8;
typedef uint32_t UINT32;
typedef uint64_t UINT64;
typedef size_t UINTN;
#else
#include <Uefi.h>
#endif
#define G201_MAP_CAPACITY 65536u
#define G201_MAX_DESCRIPTORS 512u
#define G201_MAGIC 0x003330324843504fULL /* OPCH203\0 */
#define G201_VERSION 2u
#define G201_TARGETS 7u
enum {
 G201_NOT_RUN=0,G201_READ_COMPLETE=1,
 G201_BAD_MAP=100,G201_TARGET_IS_MANAGED=101,G201_BAD_CACHE=102,
 G201_BAD_ACPI=103,G201_GATE_FAILED=104,G201_PIPE_FAILED=105,
 G201_READ_FAILED=106,G201_PRIOR_STAGE_FAILED=107,
 G201_SOURCE_PROFILE_FAILED=108,G201_SERVICE_FAILED=109,
 G201_CACHE_SYNC_FAILED=110,G201_WRITE_FAILED=111,G201_VERIFY_FAILED=112
};
typedef struct {UINT64 Base,Bytes,Capabilities,Attributes;UINT32 Kind,Valid;} G201_GCD;
typedef struct {
 UINT32 Status,MapFresh,MapCount,CompleteWords;
 UINT32 Gates[2][5],Pipe[2][4][12];
 UINT8 PixelSha256[32];
 UINT32 NonzeroWords,AcpiMatched,CacheRefreshed;
} G201_SNAPSHOT;
typedef struct {
 UINT32 MapBytes,DescriptorBytes,DescriptorVersion,SourceProfile,CpuArchPresent,Reserved;
 UINT64 MapKey,Rsdp,GetMapStatus,GetGcdStatus;
 G201_GCD Gcd[G201_TARGETS];
 UINT8 Map[G201_MAP_CAPACITY];
} G201_ENV;
typedef struct {
 UINT32 Status,Attempted,WrittenWords,VerifiedWords;
 UINT32 Gates[3][5],Pipe[3][4][12];
 UINT8 ReadbackSha256[32];
 UINT32 NonzeroWords,PriorReadAccepted,CacheSynced;
} G201_CLEAR;
typedef struct {
 UINT32 EntryCalls,ReadyCalls,BridgeCalls,WorkCalls,AfterRegistered,WorkSignaled;
 UINT64 PrepareStatus,WorkCreateStatus,ReadyCreateStatus,AfterCreateStatus,WorkSignalStatus,ReportPublishStatus;
} G203_SCHEDULE;
typedef struct {
 UINT64 Magic;
 UINT32 Version,Bytes,ReadyRuns,BeforeRuns,ExitRuns,FaultRetained;
 UINT32 CacheLineBytes,PixelCachePasses,PixelCacheLines,Reserved;
 G201_SNAPSHOT Read,Before,Exit;
 G201_CLEAR Clear;
 G201_ENV ReadEnv,ClearEnv,LateEnv;
 G203_SCHEDULE Schedule;
} G201_REPORT;
typedef struct {
 void *Context;
 int (*ReadRam)(void *,UINT64,void *,UINTN);
 int (*ReadRegister)(void *,UINT64,UINT32 *);
 int (*ReadRow)(void *,UINT32,UINT32 *);
 /* Only the AfterReady callback receives these capabilities. WriteZeroRow
  * increments the retained count after each store and accepts no address/data. */
 int (*WriteZeroRow)(void *,UINT32,UINT32 *);
 int (*SyncPixels)(void *);
} G201_IO;
int G201ValidateMap(const G201_ENV *);
int G201RamCovered(const G201_ENV *,UINT64,UINT64);
void G201Observe(const G201_ENV *,const G201_IO *,G201_SNAPSHOT *,int,int);
void G201ClearOnce(const G201_ENV *,const G201_IO *,const G201_SNAPSHOT *,G201_CLEAR *);
int G201PixelCachePlan(UINT32,UINT64 *,UINT64 *,UINT32 *);
#endif
