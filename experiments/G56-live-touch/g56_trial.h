/* SPDX-License-Identifier: MIT */
#ifndef G56_TRIAL_H
#define G56_TRIAL_H
#include "g56_power.h"
#include "g56_spi.h"
#include "g56_touch.h"
typedef struct {G56_POWER_RESULT Power;G56_SPI_RESULT Spi;G56_TOUCH_RESULT Touch;uint32_t PoweredHookCalled,SafeRelease;} G56_TRIAL_RESULT;
#endif
