#ifndef OPEN_184_PROTOCOL_H
#define OPEN_184_PROTOCOL_H
#include "sensor.h"
#define OP184_MAGIC UINT64_C(0x31534e343831474f)
#define OP184_FUNCTION 0xb21u
typedef struct {uint32_t Size,Version;uint64_t Magic,Nonce;uint32_t Count,Reserved;}OP184_REQUEST;
typedef struct {
 uint32_t Size,Version;uint64_t Magic;
 uint64_t Now100ns,Instance,D0Epoch,PrepareEpoch,ReleaseCalls,MapCalls,UnmapCalls;
 uint64_t Attempts,Completed,ValidCount,Ticks,LastSequence;
 uint32_t KernelBuild,Cpus,Irql,FirmwareMatch,Prepared,D0Active,MapCount;
 uint32_t Queued,Busy,Valid,Fault,Uncertain,ValidationCode,LastStatus,ProducerQualified,Reserved;
}OP184_STATUS_DATA;
typedef struct {OP184_STATUS_DATA Status;S183_READING Reading;S183_RESULT Result;}OP184_SNAPSHOT;
#endif
