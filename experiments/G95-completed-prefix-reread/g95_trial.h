/* SPDX-License-Identifier: MIT */
#ifndef G95_TRIAL_H
#define G95_TRIAL_H
#include "g95_power.h"
#include "g95_spi.h"
#include "g95_touch.h"
typedef struct {G95_POWER_RESULT Power;G95_SPI_RESULT Spi;G95_TOUCH_RESULT Touch;uint32_t PoweredHookCalled,SafeRelease;} G95_TRIAL_RESULT;
#endif
