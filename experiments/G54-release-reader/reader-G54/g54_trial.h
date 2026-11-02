/* SPDX-License-Identifier: MIT */
#ifndef G54_TRIAL_H
#define G54_TRIAL_H
#include "g54_power.h"
#include "g54_spi.h"
#include "g54_touch.h"
typedef struct {G54_POWER_RESULT Power;G54_SPI_RESULT Spi;G54_TOUCH_RESULT Touch;uint32_t PoweredHookCalled,SafeRelease;} G54_TRIAL_RESULT;
#endif
