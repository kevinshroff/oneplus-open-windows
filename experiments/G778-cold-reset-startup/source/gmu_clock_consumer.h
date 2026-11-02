/* SPDX-License-Identifier: MIT */
#pragma once
#include "gmu_clock_interface.h"
typedef struct {OPEN_GMU_CLOCK_INTERFACE Api;PFILE_OBJECT File;ULONGLONG Token;BOOLEAN Bound;}OPEN_GMU_CLOCK_BINDING;
NTSTATUS OpenGmuClockOpen(OPEN_GMU_CLOCK_BINDING*);
NTSTATUS OpenGmuClockClose(OPEN_GMU_CLOCK_BINDING*);
NTSTATUS OpenGmuClockConnect(OPEN_GMU_CLOCK_BINDING*,const OPEN_CLOCK_CLIENT*);
NTSTATUS OpenGmuClockDisconnect(OPEN_GMU_CLOCK_BINDING*);
