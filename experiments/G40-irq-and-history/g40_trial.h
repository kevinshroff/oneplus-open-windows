/* SPDX-License-Identifier: MIT */
#ifndef G40_TRIAL_H
#define G40_TRIAL_H
#include "g40_power.h"
#include "g40_spi.h"
#include "g40_touch.h"
typedef struct {G40_POWER_RESULT Power;G40_SPI_RESULT Spi;G40_TOUCH_RESULT Touch;uint32_t PoweredHookCalled,SafeRelease;} G40_TRIAL_RESULT;
#endif
