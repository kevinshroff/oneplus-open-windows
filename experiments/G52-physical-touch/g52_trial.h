/* SPDX-License-Identifier: MIT */
#ifndef G52_TRIAL_H
#define G52_TRIAL_H
#include "g52_power.h"
#include "g52_spi.h"
#include "g52_touch.h"
typedef struct {G52_POWER_RESULT Power;G52_SPI_RESULT Spi;G52_TOUCH_RESULT Touch;uint32_t PoweredHookCalled,SafeRelease;} G52_TRIAL_RESULT;
#endif
