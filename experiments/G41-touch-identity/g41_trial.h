/* SPDX-License-Identifier: MIT */
#ifndef G41_TRIAL_H
#define G41_TRIAL_H
#include "g41_power.h"
#include "g41_spi.h"
#include "g41_touch.h"
typedef struct {G41_POWER_RESULT Power;G41_SPI_RESULT Spi;G41_TOUCH_RESULT Touch;uint32_t PoweredHookCalled,SafeRelease;} G41_TRIAL_RESULT;
#endif
