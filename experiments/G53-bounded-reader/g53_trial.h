/* SPDX-License-Identifier: MIT */
#ifndef G53_TRIAL_H
#define G53_TRIAL_H
#include "g53_power.h"
#include "g53_spi.h"
#include "g53_touch.h"
typedef struct {G53_POWER_RESULT Power;G53_SPI_RESULT Spi;G53_TOUCH_RESULT Touch;uint32_t PoweredHookCalled,SafeRelease;} G53_TRIAL_RESULT;
#endif
