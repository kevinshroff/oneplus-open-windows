/* SPDX-License-Identifier: MIT */
#ifndef G50_TRIAL_H
#define G50_TRIAL_H
#include "g50_power.h"
#include "g50_spi.h"
#include "g50_touch.h"
typedef struct {G50_POWER_RESULT Power;G50_SPI_RESULT Spi;G50_TOUCH_RESULT Touch;uint32_t PoweredHookCalled,SafeRelease;} G50_TRIAL_RESULT;
#endif
