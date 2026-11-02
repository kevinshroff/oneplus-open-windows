/* SPDX-License-Identifier: MIT */
#ifndef G43_TRIAL_H
#define G43_TRIAL_H
#include "g43_power.h"
#include "g43_spi.h"
#include "g43_touch.h"
typedef struct {G43_POWER_RESULT Power;G43_SPI_RESULT Spi;G43_TOUCH_RESULT Touch;uint32_t PoweredHookCalled,SafeRelease;} G43_TRIAL_RESULT;
#endif
