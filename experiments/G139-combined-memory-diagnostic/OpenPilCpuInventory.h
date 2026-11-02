/* SPDX-License-Identifier: MIT */
#ifndef OPEN_PIL_CPU_INVENTORY_H
#define OPEN_PIL_CPU_INVENTORY_H
typedef unsigned long long P139_U64;
typedef P139_U64 (*P139_AT_QUERY)(void *,P139_U64,unsigned);
#define P139_WINDOW_START 0x9e980000ULL
#define P139_WINDOW_END   0xa3280000ULL
#define P139_PAGE_COUNT   18688ULL
typedef struct {
 P139_U64 El,Pages,Queries,ReadFaults,WriteFaults,ReadAliases,WriteAliases,TagDifferences;
 P139_U64 FirstFault,FaultReadPar,FaultWritePar,FirstAlias,AliasReadPar,AliasWritePar;
 P139_U64 FirstTagDifference,TagReadPar,TagWritePar;
 P139_U64 ReadTags[256],WriteTags[256];
 unsigned Complete,Refusal;
} P139_CPU_INVENTORY;
/* Fixed stage-1 translation queries only. No load/store to the target range.
 * Attribute bytes stay raw; collection completion is never a permission grant. */
unsigned OpenCollectPilCpu(P139_CPU_INVENTORY *,P139_AT_QUERY,void *,P139_U64);
P139_U64 OpenDspCurrentEl(void);
P139_U64 OpenDspAt(void *,P139_U64,unsigned);
#endif
