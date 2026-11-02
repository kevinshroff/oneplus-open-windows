/* Actual OPEN0515 PnP/D0 bootstrap owner. No Display or user IOCTL surface. */
#pragma once
#include <ntifs.h>
#include "native_bootstrap.h"
#define OGO_TAG 'OsGO'
enum {OGO_NEW,OGO_LOWER_STARTED,OGO_RAM,OGO_D0,OGO_HOLD,OGO_BANK,OGO_IRQ,OGO_TRANSLATION,OGO_RETAINED,OGO_CLOSED};
typedef struct {
 PDEVICE_OBJECT Pdo,Lower,Fdo;IO_REMOVE_LOCK Remove;KMUTEX Lock,RamLock;
 KEVENT Revoke,OperationDone;volatile LONG Revoked,Once;
 BOOLEAN Started,D0,Removing,StopPending,RemovePending,ThreadLive,PowerBusy,Uncertain,Enabled;
 PETHREAD OperationThread,RamThread;ULONGLONG Generation,Serial,RunId;
 PCM_RESOURCE_LIST Resources;SIZE_T ResourceBytes;
 G515_LIFE Life;G482_BINDING Io;CGH_NATIVE Hold;OPEN_LOCAL_BANK_CLIENT Bank;PVOID Fault;
 G321_RUNTIME*Gmu;
 G321_INACTIVE_RUNTIME*Ram;OAS_BOOTSTRAP*Active;
 PVOID Input[6];g196_inputs Inputs;
 ULONG Phase;NTSTATUS InputStatus,Status,CleanupStatus,GmuStatus;
}OGO_CONTEXT;
VOID LogOpen(VOID);VOID LogPrint(PCSTR,...);
NTSTATUS OgoLoadInputs(OGO_CONTEXT*);VOID OgoFreeInputs(OGO_CONTEXT*);
NTSTATUS OgoBootstrap(OGO_CONTEXT*);
BOOLEAN OgoSafe(OGO_CONTEXT*);
/* Initial RAM scope proves no publication only. Actual CGH/IRQ/bank/NS objects
 * supply activation authority. These callbacks never pretend PAS/HFI success. */

NTSTATUS OgoRunGmu(OGO_CONTEXT*);
NTSTATUS OgoGmuCurrent(G321_RUNTIME*);
NTSTATUS OgoGmuHandoff(G321_RUNTIME*);
