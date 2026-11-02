#ifndef OPEN_PARENT_CONSUMER_H
#define OPEN_PARENT_CONSUMER_H
#include "open_parent_interface.h"
typedef struct {
 OPEN_PARENT_INTERFACE Api;PFILE_OBJECT File;BOOLEAN Bound;
 ULONGLONG Instance,PrepareEpoch,D0Epoch;
} OPEN_PARENT_BINDING;
BOOLEAN OpenExactHardwareId(PDEVICE_OBJECT Pdo,PCWSTR Expected);
NTSTATUS OpenParentBind(OPEN_PARENT_BINDING*);
NTSTATUS OpenParentRead(OPEN_PARENT_BINDING*,ULONG*,ULONG*);
VOID OpenParentUnbind(OPEN_PARENT_BINDING*);
#endif
