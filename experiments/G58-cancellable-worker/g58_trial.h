/* SPDX-License-Identifier: MIT */
#ifndef G58_TRIAL_H
#define G58_TRIAL_H
#include "g58_power.h"
#include "g58_spi.h"
#include "g58_touch.h"
typedef struct {G58_POWER_RESULT Power;G58_SPI_RESULT Spi;G58_TOUCH_RESULT Touch;uint32_t PoweredHookCalled,SafeRelease;} G58_TRIAL_RESULT;
#endif
