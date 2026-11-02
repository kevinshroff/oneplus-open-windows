/* SPDX-License-Identifier: MIT */
#ifndef G59_TRIAL_H
#define G59_TRIAL_H
#include "g59_power.h"
#include "g59_spi.h"
#include "g59_touch.h"
typedef struct {G59_POWER_RESULT Power;G59_SPI_RESULT Spi;G59_TOUCH_RESULT Touch;uint32_t PoweredHookCalled,SafeRelease;} G59_TRIAL_RESULT;
#endif
