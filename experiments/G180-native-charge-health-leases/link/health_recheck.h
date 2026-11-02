/* SPDX-License-Identifier: MIT; trusted kernel measurement acceptance only. */
#ifndef OPEN_CHARGE_HEALTH_RECHECK_H
#define OPEN_CHARGE_HEALTH_RECHECK_H
#include "health_capture.h"
/* Input must be CHValidate output from the fixed kernel RESULT transport.
 * No IOCTL accepts CH_HEALTH. Rechecks time and semantic limits after I/O. */
uint32_t CHRecheck(const CH_HEALTH*,uint64_t nonce,uint64_t now100ns,
 uint64_t previousNonce,uint64_t previousGaugeEnd100ns,uint32_t role);
#endif
