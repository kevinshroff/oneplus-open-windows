/* SPDX-License-Identifier: MIT */
#ifndef G100_KEYS_H
#define G100_KEYS_H
#include "g137_capture.h"
typedef struct {
 void *Frozen,*Owner;
 int (*Available)(void *);
 volatile LONG Attempts,Ready,Fault,Maps;
 volatile LONG64 Sequence;
 G137_LEDGER Ledger;
} G100_KEYS;
NTSTATUS G100KeysInitialize(G100_KEYS *,void *,int (*)(void *));
void G100KeysFree(G100_KEYS *);
int G100KeysTryControl(G100_KEYS *,WDFREQUEST,size_t,size_t,ULONG);
#endif
