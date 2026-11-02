/* SPDX-License-Identifier: MIT */
#ifndef G57_TRIAL_H
#define G57_TRIAL_H
#include "g57_power.h"
#include "g57_spi.h"
#include "g57_touch.h"
typedef struct {G57_POWER_RESULT Power;G57_SPI_RESULT Spi;G57_TOUCH_RESULT Touch;uint32_t PoweredHookCalled,SafeRelease;} G57_TRIAL_RESULT;
#endif
