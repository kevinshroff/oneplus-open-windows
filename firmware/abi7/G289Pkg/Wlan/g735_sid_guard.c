/* SPDX-License-Identifier: MIT
 * Read-only bridge between actual G403 SID preparation and SMMU admission.
 * The address comes from the producer's verified hash, never a copied slot.
 */
#include "g735_smmu_identity.h"
int G735VerifyPreparedSid(const G403_IO*i,const G403_RESULT*s,G735_RESULT*r){
 if(!i||!i->Read32||!s||!r)return 1;
 if(!s->Prepared||s->Stage!=5||s->Code||s->Uncertain||!s->Attempted||
    s->Hash>=256||s->Entry!=0x01000100u||s->After[s->Hash]!=s->Entry||
    (s->AfterCfg&1u)){r->GateCode=3;return 1;}
 r->SidHash=s->Hash;r->SidTableAddress=G403_SID_TABLE_BASE+4*(uint64_t)s->Hash;
 if(i->Read32(i->Context,G403_SID_CFG,&r->ParfCfg)||r->ParfCfg!=s->AfterCfg){r->GateCode=2;return 1;}
 if(i->Read32(i->Context,r->SidTableAddress,&r->SidEntry)||r->SidEntry!=s->Entry){r->GateCode=3;return 1;}
 return 0;
}
