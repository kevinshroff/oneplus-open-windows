/* SPDX-License-Identifier: MIT. Same-owner transport; contains no hardware IO. */
#ifndef POWER291_H
#define POWER291_H
#include "buttons192.h"
typedef int (*P291_SUBMIT)(void *, const uint8_t report[2]);
typedef struct {
 B192_STREAM Stream;
 P291_SUBMIT Submit;
 void *Context;
 uint32_t Fault, Stopped, AcceptedDown, DeliveryUncertain, Rearming;
 uint64_t GapRearms;
} P291;
/* Caller supplies only samples acquired by its real D0 owner; epoch/sequence
 * are consistency checks, not ownership grants. Single serialized caller.
 * Physically qualified mapping and reviewed Windows button policy required
 * before any native caller connects this adapter. */
void P291Init(P291 *, uint64_t epoch, P291_SUBMIT, void *);
uint32_t P291Step(P291 *, uint64_t epoch, uint64_t sequence, const B192_SAMPLE *);
/* Stop acquisition and join the owner worker BEFORE this call or VHF disposal.
 * Stop attempts release even after a failed down whose delivery is uncertain. */
/* Checked release and disarm after missing input; real idle samples rearm. */
int P291Suspend(P291 *);
int P291Stop(P291 *);
extern const uint8_t P291Descriptor[];
extern const uint32_t P291DescriptorBytes;
#endif
