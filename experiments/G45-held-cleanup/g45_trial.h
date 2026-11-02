/* SPDX-License-Identifier: MIT */
#ifndef G45_TRIAL_H
#define G45_TRIAL_H
#include "g45_power.h"
#include "g45_spi.h"
#include "g45_touch.h"
typedef struct {G45_POWER_RESULT Power;G45_SPI_RESULT Spi;G45_TOUCH_RESULT Touch;uint32_t PoweredHookCalled,SafeRelease;} G45_TRIAL_RESULT;
#endif
