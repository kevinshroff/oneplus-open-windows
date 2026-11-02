/* SPDX-License-Identifier: MIT */
#ifndef G92_TRIAL_H
#define G92_TRIAL_H
#include "g92_power.h"
#include "g92_spi.h"
#include "g92_touch.h"
typedef struct {G92_POWER_RESULT Power;G92_SPI_RESULT Spi;G92_TOUCH_RESULT Touch;uint32_t PoweredHookCalled,SafeRelease;} G92_TRIAL_RESULT;
#endif
