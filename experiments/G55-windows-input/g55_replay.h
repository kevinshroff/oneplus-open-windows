/* SPDX-License-Identifier: MIT */
#ifndef G55_REPLAY_H
#define G55_REPLAY_H
#include "g55_lifecycle.h"
typedef struct {
 void*Context;
 int(*Submit)(void*,const uint8_t[64]);
 int(*Wait25ms)(void*);
 uint16_t(*Scan100us)(void*);
}G55_REPLAY_IO;
typedef struct {
 uint32_t Attempted,Submitted,Accepted,CleanupAttempted,CleanupAccepted,Complete,Error;
}G55_REPLAY_RESULT;
/* One invocation per PnP instance is enforced by the native dispatch.
 * At most four captured frames plus one best-effort release of accepted IDs.
 * No supplied raw packets, coordinates or arbitrary input are accepted. */
int G55Replay(G55_STATE*,const G55_REPLAY_IO*,G55_REPLAY_RESULT*);
#endif
