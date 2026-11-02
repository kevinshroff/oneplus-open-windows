/* SPDX-License-Identifier: MIT */
#ifndef G46_TRIAL_H
#define G46_TRIAL_H
#include "g46_power.h"
#include "g46_spi.h"
#include "g46_touch.h"
typedef struct {G46_POWER_RESULT Power;G46_SPI_RESULT Spi;G46_TOUCH_RESULT Touch;uint32_t PoweredHookCalled,SafeRelease;} G46_TRIAL_RESULT;
#endif
