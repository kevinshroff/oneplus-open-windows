/* SPDX-License-Identifier: MIT */
#ifndef G49_TRIAL_H
#define G49_TRIAL_H
#include "g49_power.h"
#include "g49_spi.h"
#include "g49_touch.h"
typedef struct {G49_POWER_RESULT Power;G49_SPI_RESULT Spi;G49_TOUCH_RESULT Touch;uint32_t PoweredHookCalled,SafeRelease;} G49_TRIAL_RESULT;
#endif
