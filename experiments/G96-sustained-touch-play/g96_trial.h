/* SPDX-License-Identifier: MIT */
#ifndef G96_TRIAL_H
#define G96_TRIAL_H
#include "g96_power.h"
#include "g96_spi.h"
#include "g96_touch.h"
typedef struct {G96_POWER_RESULT Power;G96_SPI_RESULT Spi;G96_TOUCH_RESULT Touch;uint32_t PoweredHookCalled,SafeRelease;} G96_TRIAL_RESULT;
#endif
