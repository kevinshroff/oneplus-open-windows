/* SPDX-License-Identifier: MIT */
#ifndef G47_TRIAL_H
#define G47_TRIAL_H
#include "g47_power.h"
#include "g47_spi.h"
#include "g47_touch.h"
typedef struct {G47_POWER_RESULT Power;G47_SPI_RESULT Spi;G47_TOUCH_RESULT Touch;uint32_t PoweredHookCalled,SafeRelease;} G47_TRIAL_RESULT;
#endif
