/* SPDX-License-Identifier: MIT */
#ifndef G401_TRANSPORT_H
#define G401_TRANSPORT_H
#include <stdint.h>
#include <stddef.h>
#define G401_BAD 1
#define G401_NOT_READY 2
#define G401_IO 3
#define G401_UNSUPPORTED 4
typedef struct {
 void *Context;
 int (*Read32)(void*,uint64_t,uint32_t*);
 int (*Write32)(void*,uint64_t,uint32_t);
 int (*StallUs)(void*,uint32_t);
} G401_IOPS;
/* Caller is the existing single pre-EBS coordinator, after current G289 RC
 * identity and fresh G200 physical access admission, with full CFG1MiB mapped.
 * This function is not an OS driver, lease generator or ACPI publisher.
 */
typedef struct {
 uint32_t Attempted,Stage,FirstError,WriteAttempts,Reads,Version,VersionType;
 uint32_t RootId,EndpointId,CommandBefore,CommandAfter,LinkBefore,LinkAfter;
 uint32_t OldAtu[7],NewAtu[7],Identities[256];
 uint32_t EnablePolls,SeparationValid,RetainUntilReset;
 uint32_t MemOld[7],MemNew[7],MemPolls,MemValid,MemUsedExisting;
 uint32_t RootHeader,RootCommandBefore,RootCommandAfter,RootBusBefore,RootBusAfter;
 uint32_t RootMemoryBefore,RootMemoryAfter,RootForwardingValid;
 uint32_t Cfg1Old[7],Cfg1New[7],Cfg1Polls,Cfg1UsedExisting;
} G401_REPORT;
int G401PrepareBus1Ecam(G401_REPORT*,const G401_IOPS*);
/* Validates complete original table and replaces only segment0 allocation
 * start/end with1; base remains60000000 (never60100000). No install operation.
 */
int G401BuildMcfg(const G401_REPORT*,const uint8_t*,size_t,uint8_t*,size_t);
#endif
