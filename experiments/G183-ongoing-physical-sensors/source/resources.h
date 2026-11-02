/* Generated fixed resources, not a user-selected mapping interface. */
#ifndef OP182_RESOURCES_H
#define OP182_RESOURCES_H
#include <stdint.h>
#include <stddef.h>
#define OP182_RESOURCE_COUNT 20u
typedef struct {uint64_t Base;uint32_t Bytes,Write,Cache,Share;}OP182_RESOURCE;
static const OP182_RESOURCE OP182Expected[OP182_RESOURCE_COUNT]={
 {UINT64_C(0x152000),0x1000,0,0,0}, /* GCC votes */
 {UINT64_C(0x11e000),0x1000,0,0,0}, /* primary root/branch clocks */
 {UINT64_C(0x117000),0x1000,0,0,0}, /* secondary root/branch clocks */
 {UINT64_C(0x123000),0x1000,0,0,0}, /* shared controller branch clocks */
 {UINT64_C(0xf100000),0x1000,0,0,0}, /* primary SDA pin */
 {UINT64_C(0xf101000),0x1000,0,0,0}, /* primary SCL pin */
 {UINT64_C(0xf116000),0x1000,0,0,0}, /* secondary SDA pin */
 {UINT64_C(0xf117000),0x1000,0,0,0}, /* secondary SCL pin */
 {UINT64_C(0x880000),0x1000,1,0,0}, /* primary GENI I2C engine */
 {UINT64_C(0x8c0000),0x1000,0,0,0}, /* primary QUP wrapper */
 {UINT64_C(0x98c000),0x1000,1,0,0}, /* secondary I2C hub engine */
 {UINT64_C(0xc400000),0x1000,0,0,0}, /* SPMI arbiter identity */
 {UINT64_C(0xc402000),0x1000,0,0,0}, /* SPMI APID map */
 {UINT64_C(0xc42d000),0x1000,0,0,0}, /* SPMI APID owners */
 {UINT64_C(0xc443000),0x1000,1,0,0}, /* fixed SPMI read-command pages A */
 {UINT64_C(0xc445000),0x1000,1,0,0}, /* fixed SPMI read-command pages B */
 {UINT64_C(0x81a04000),0x10000,0,1,0}, /* pinned firmware FDT */
 {UINT64_C(0x81eff000),0x1000,0,0,0}, /* SMEM TOC */
 {UINT64_C(0x81e9f000),0x60000,1,0,0}, /* AP/DSP SMEM partition */
 {UINT64_C(0x408000),0x1000,1,0,0}, /* qualified IPCC doorbell page */
};
uint32_t Op182Validate(const OP182_RESOURCE*,const OP182_RESOURCE*,size_t);
#endif
