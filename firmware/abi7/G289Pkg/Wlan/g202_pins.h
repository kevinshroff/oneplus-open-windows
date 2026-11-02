/* SPDX-License-Identifier: MIT — source-only pre-OS TLMM adapter. */
#ifndef G202_PINS_H
#define G202_PINS_H
#include "g202_rpmh_abi.h"
typedef struct {
 uint64_t Revision;
 G202_STATUS(*ConfigGpio)(uint32_t,uint32_t);
 G202_STATUS(*ConfigGpioGroup)(uint32_t,uint32_t*,uint32_t);
 G202_STATUS(*GpioIn)(uint32_t,uint32_t*);
 G202_STATUS(*GpioOut)(uint32_t,uint32_t);
 G202_STATUS(*SetInactiveConfig)(uint32_t,uint32_t);
}G202_TLMM_PROTOCOL;
_Static_assert(offsetof(G202_TLMM_PROTOCOL,GpioOut)==32,"Shipped TLMM GpioOut slot");
typedef struct {void*Context;G202_STATUS(*Read32)(void*,uint64_t,uint32_t*);G202_STATUS(*Stall)(void*,uint32_t);}G202_PIN_IO;
typedef struct {uint32_t Cfg,InOut,IrqCfg;}G202_PIN_WORDS;
typedef struct {
 G202_TLMM_PROTOCOL*Tlmm;G202_PIN_IO Io;
 G202_PIN_WORDS Before[4];uint32_t Touched,Prepared,Active,Uncertain;
 G202_STATUS FirstError;
}G202_PINS;
/* Fixed order PERST94,WAKE96,CLKREQ95,WLAN_EN80; GPIO83 is observation-only. */
uint32_t G202PinPacked(uint32_t,uint32_t,uint32_t,uint32_t,uint32_t);
G202_STATUS G202PinObserve(G202_PINS*,G202_PIN_WORDS[4],uint32_t*Selector);
/* Deliberately cold-only: both WLAN_EN/PERST must be GPIO0 and sampled low,
 * with no enabled IRQ or active EGPIO path. No caller-supplied ready bits.
 * This primitive does not prove other firmware users relinquished the pins.
 */
G202_STATUS G202PinPrepare(G202_PINS*);
/* Requires a separately reviewed rail/ref/parent coordinator. No integrated
 * firmware entrypoint calls this function in this source package. */
G202_STATUS G202PinActivate(G202_PINS*);
G202_STATUS G202PinDeactivate(G202_PINS*);
/* Only certain, deactivated, still-asserted state can restore own pin edits. */
G202_STATUS G202PinRestore(G202_PINS*);
G202_STATUS G202BindEfiPins(G202_PINS*);
#endif
