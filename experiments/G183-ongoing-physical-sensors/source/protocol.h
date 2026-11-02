#ifndef OPEN_183_PROTOCOL_H
#define OPEN_183_PROTOCOL_H
#include "sensor.h"
#define OP183_MAGIC UINT64_C(0x31534e333831474f)
#define OP183_FUNCTION 0xb20u
typedef struct {uint32_t Size,Version;uint64_t Magic,Nonce;uint32_t Count,Reserved;}OP183_REQUEST;
typedef struct {
 uint32_t Size,Version;uint64_t Magic;
 uint64_t Now100ns,Instance,D0Epoch,PrepareEpoch,ReleaseCalls,MapCalls,UnmapCalls;
 uint64_t Attempts,Completed,ValidCount,Ticks,LastSequence;
 uint32_t KernelBuild,Cpus,Irql,FirmwareMatch,Prepared,D0Active,MapCount;
 uint32_t Queued,Busy,Valid,Fault,Uncertain,ValidationCode,LastStatus,ProducerQualified,Reserved;
}OP183_STATUS_DATA;
typedef struct {OP183_STATUS_DATA Status;S183_READING Reading;S183_RESULT Result;}OP183_SNAPSHOT;
#endif
