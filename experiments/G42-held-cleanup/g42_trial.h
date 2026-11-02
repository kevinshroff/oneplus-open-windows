/* SPDX-License-Identifier: MIT */
#ifndef G42_TRIAL_H
#define G42_TRIAL_H
#include "g42_power.h"
#include "g42_spi.h"
#include "g42_touch.h"
typedef struct {G42_POWER_RESULT Power;G42_SPI_RESULT Spi;G42_TOUCH_RESULT Touch;uint32_t PoweredHookCalled,SafeRelease;} G42_TRIAL_RESULT;
#endif
