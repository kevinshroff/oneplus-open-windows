/* SPDX-License-Identifier: MIT */
#ifndef G39_TRIAL_H
#define G39_TRIAL_H
#include "g39_power.h"
#include "g39_spi.h"
#include "g39_touch.h"
typedef struct {G39_POWER_RESULT Power;G39_SPI_RESULT Spi;G39_TOUCH_RESULT Touch;uint32_t PoweredHookCalled,SafeRelease;} G39_TRIAL_RESULT;
#endif
