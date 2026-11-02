/* SPDX-License-Identifier: MIT. Integration source, not installed or linked. */
#ifndef VHF291_H
#define VHF291_H
#include <ntddk.h>
#include <wdf.h>
#include <vhf.h>
#include "power291.h"
typedef struct {P291 Power;VHFHANDLE Vhf;NTSTATUS LastSubmit;} VHF291;
/* Caller zero-initializes once; serialize create/step/stop under device life. */
NTSTATUS Vhf291Create(VHF291 *, WDFDEVICE, uint64_t epoch);
/* Called only after acquisition worker has stopped/joined. */
int Vhf291StopDelete(VHF291 *);
#endif
