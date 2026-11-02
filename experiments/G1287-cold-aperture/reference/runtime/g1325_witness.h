/* Fixed read-only, pre-release persistence witness. No device execution proof. */
#pragma once
#ifndef OGO_GPU_PRE_RELEASE_WITNESS
#define OGO_GPU_PRE_RELEASE_WITNESS 0
#endif
#if OGO_GPU_PRE_RELEASE_WITNESS != 0 && OGO_GPU_PRE_RELEASE_WITNESS != 1
#error OGO_GPU_PRE_RELEASE_WITNESS must be exactly 0 or 1
#endif
#if OGO_GPU_PRE_RELEASE_WITNESS
/* Scalar types are supplied by the actual owner or the host qualification. */
typedef struct {ULONG Offset,Width,Compare;ULONGLONG Expected;} G1325_ITEM;
typedef struct {ULONGLONG Value[2][25];ULONG Valid[2],Mismatch,Unstable,Fault;ULONG BackingChecked,BackingMismatch;} G1325_REPORT;
typedef struct {
 void*Context;
 int(*Current)(void*);
 int(*Read)(void*,ULONG,ULONG,ULONGLONG*);
 int(*Backing)(void*,ULONG*,ULONG*);
} G1325_OPS;
/* All read offsets are fixed here. Fault registers are read first so a later
 * refusal preserves already observed syndrome. No ACK/clear callback exists. */
static inline void G1325Plan(G1325_ITEM p[25],ULONGLONG root,ULONG smr,ULONG s2cr,ULONG nscr,ULONG nsacr){
 const G1325_ITEM fixed[25]={
  {0x48,4,0,0},{0x50,4,0,0},{0x54,4,0,0},{0x58,4,0,0},
  {0x20058,4,1,0x400},{0x20060,8,0,0},{0x20068,4,0,0},{0x2006c,4,0,0},
  {0x1000,4,1,0x1f300},{0x1800,4,1,1},{0x20000,4,1,0xc00067},
  {0x20004,4,1,0x32b},{0x20010,4,1,0x38071},{0x20020,8,1,0},
  {0x20028,8,1,0},{0x20030,4,1,0x803519},{0x20038,4,1,0xf404ff44},
  {0x2003c,4,1,0xefe4},{0x804,4,1,0},{0xc04,4,1,0},
  {0,4,1,0},{0x10,4,1,0},{0x20,4,1,0x4c017e18},{0x24,4,1,0x40000016},{0x1400,4,0,0}};
 for(ULONG i=0;i<25;i++)p[i]=fixed[i];
 p[13].Expected=root;p[18].Expected=smr;p[19].Expected=s2cr;
 p[20].Expected=nscr;p[21].Expected=nsacr;
}
/* 0 means complete clean observation only; caller MUST refuse SQE release even
 * then. Guard each access; never read after a failed current/authority check. */
static inline int G1325Collect(const G1325_OPS*o,const G1325_ITEM p[25],G1325_REPORT*r){
 if(!o||!p||!r||!o->Current||!o->Read||!o->Backing)return -1;
 for(ULONG pass=0;pass<2;pass++)for(ULONG i=0;i<25;i++){
  ULONGLONG v=0;if(o->Current(o->Context)||o->Read(o->Context,p[i].Offset,p[i].Width,&v))return -1;
  r->Value[pass][i]=v;r->Valid[pass]|=1u<<i;
  if(v==(p[i].Width==8?~(ULONGLONG)0:(ULONGLONG)0xffffffffu))return -1;
  if(p[i].Compare&&v!=p[i].Expected)r->Mismatch|=1u<<i;
  if(pass&&v!=r->Value[0][i])r->Unstable|=1u<<i;
  if((i==0&&v)||(i==4&&v!=0x400))r->Fault|=1u<<i;
 }
 if(o->Current(o->Context)||o->Backing(o->Context,&r->BackingChecked,&r->BackingMismatch))return -1;
 return r->Mismatch||r->Unstable||r->Fault||r->BackingMismatch?1:0;
}
#endif
