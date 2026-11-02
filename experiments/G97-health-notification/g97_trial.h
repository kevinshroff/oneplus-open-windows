/* SPDX-License-Identifier: MIT */
#ifndef G97_TRIAL_H
#define G97_TRIAL_H
#include "g97_power.h"
#include "g97_spi.h"
#include "g97_touch.h"
typedef struct {G97_POWER_RESULT Power;G97_SPI_RESULT Spi;G97_TOUCH_RESULT Touch;uint32_t PoweredHookCalled,SafeRelease;} G97_TRIAL_RESULT;
#endif
