/* SPDX-License-Identifier: MIT
 * Fixed address-translation instructions only. They do not access the target
 * data or change page tables. Restore PAR and the prior interrupt mask on return.
 * ARM Architecture Registers: https://documentation-service.arm.com/static/6023d5362cb3723f202089b8
 */
#include "OpenDspAdmission.h"
OP_U64 OpenDspCurrentEl(void){OP_U64 el;__asm__ volatile("mrs %0, CurrentEL":"=r"(el));return (el>>2)&3;}
#define QUERY(instruction) __asm__ volatile( \
 "mrs %0, daif\n\tmsr daifset, #2\n\tmrs %1, par_el1\n\t" instruction ", %3\n\t" \
 "isb\n\tmrs %2, par_el1\n\tmsr par_el1, %1\n\tmsr daif, %0\n\tisb" \
 : "=&r"(mask),"=&r"(prior),"=&r"(par):"r"(address):"memory")
OP_U64 OpenDspAt(void *context,OP_U64 address,unsigned write)
{
 OP_U64 mask,prior,par,el=*(const OP_U64 *)context;
 if(el==1){if(write){QUERY("at s1e1w");}else{QUERY("at s1e1r");}}
 else if(el==2){if(write){QUERY("at s1e2w");}else{QUERY("at s1e2r");}}
 else return 1;
 return par;
}
