#pragma once
#include <ntifs.h>
/* A reservation, never a translated mapping/physical-stop/secure token. */
typedef struct {ULONGLONG Id,Generation,Serial;ULONG Sid,Bank,Asid,Slot;BOOLEAN Qualified,Referenced;}OGU_TOKEN;
