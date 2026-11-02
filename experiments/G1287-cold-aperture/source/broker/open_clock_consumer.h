#ifndef OPEN_CLOCK_CONSUMER_H
#define OPEN_CLOCK_CONSUMER_H
#include "open_clock_interface.h"
typedef struct {OPEN_CLOCK_INTERFACE Api;PFILE_OBJECT File;ULONGLONG Token;BOOLEAN Bound;}OPEN_CLOCK_BINDING;
/* Fresh storage; caller supplies its genuine held source owner callbacks. */
NTSTATUS OpenClockOpen(OPEN_CLOCK_BINDING*);
NTSTATUS OpenClockClose(OPEN_CLOCK_BINDING*);
NTSTATUS OpenClockConnect(OPEN_CLOCK_BINDING*,const OPEN_CLOCK_CLIENT*);
/* Calls actual Current/Drained proof before releasing token; failure retains. */
NTSTATUS OpenClockDisconnect(OPEN_CLOCK_BINDING*);
#endif
