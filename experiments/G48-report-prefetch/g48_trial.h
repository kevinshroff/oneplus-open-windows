/* SPDX-License-Identifier: MIT */
#ifndef G48_TRIAL_H
#define G48_TRIAL_H
#include "g48_power.h"
#include "g48_spi.h"
#include "g48_touch.h"
typedef struct {G48_POWER_RESULT Power;G48_SPI_RESULT Spi;G48_TOUCH_RESULT Touch;uint32_t PoweredHookCalled,SafeRelease;} G48_TRIAL_RESULT;
#endif
