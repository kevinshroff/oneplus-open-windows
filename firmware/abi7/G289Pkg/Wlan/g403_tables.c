/* SPDX-License-Identifier: MIT */
#include "g403_platform.h"
#include "G403TableData.h"
static int same(const uint8_t*a,const uint8_t*b,size_t n){for(size_t i=0;i<n;i++)if(a[i]!=b[i])return 0;return 1;}
static void copy(uint8_t*a,const uint8_t*b,size_t n){for(size_t i=0;i<n;i++)a[i]=b[i];}
_Static_assert(sizeof(G403Apic)==G403_APIC_BYTES,"APIC size");
_Static_assert(sizeof(G403Iort)==G403_IORT_BYTES,"IORT size");
int G403BuildTables(const uint8_t*a,size_t an,const uint8_t*i,size_t in,uint8_t*ao,size_t aon,uint8_t*io,size_t ion){
 if(!a||!i||!ao||!io||an!=sizeof(G403OldApic)||in!=sizeof(G403OldIort)||aon<G403_APIC_BYTES||ion<G403_IORT_BYTES)return 1;
 if(!same(a,G403OldApic,an)||!same(i,G403OldIort,in))return 2;
 copy(ao,G403Apic,G403_APIC_BYTES);copy(io,G403Iort,G403_IORT_BYTES);return 0;
}
