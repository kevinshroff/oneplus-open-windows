/* SPDX-License-Identifier: MIT */
#ifndef G44_TRIAL_H
#define G44_TRIAL_H
#include "g44_power.h"
#include "g44_spi.h"
#include "g44_touch.h"
typedef struct {G44_POWER_RESULT Power;G44_SPI_RESULT Spi;G44_TOUCH_RESULT Touch;uint32_t PoweredHookCalled,SafeRelease;} G44_TRIAL_RESULT;
#endif
