/* SPDX-License-Identifier: MIT */
#ifndef G98_TRIAL_H
#define G98_TRIAL_H
#include "g98_power.h"
#include "g98_spi.h"
#include "g98_touch.h"
typedef struct {G98_POWER_RESULT Power;G98_SPI_RESULT Spi;G98_TOUCH_RESULT Touch;uint32_t PoweredHookCalled,SafeRelease;} G98_TRIAL_RESULT;
#endif
