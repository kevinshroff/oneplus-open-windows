/* Pure RAM eligibility of the sensor-frame subsystem, NOT power/grant proof.
 * ParentCurrent separately holds actual WDF lock and requires Prepared/current
 * D0/maps/Cancel0 plus fresh stable physical RO clock reads. Never clears the
 * sensor Fault/Valid0 state or restarts acquisition. */
#ifndef OPEN_PARENT_CLOCK_DATA_POLICY_H
#define OPEN_PARENT_CLOCK_DATA_POLICY_H
#include "protocol.h"
static int OpParentFramePermitsClock(const OP184_STATUS_DATA*d,const S183_RESULT*r){
 if(!d||d->Uncertain)return 0;
 if(!d->Fault)return 1;
 if(d->Fault!=1||d->ValidationCode!=S183_DATA||d->Valid||d->Busy||d->Queued||!d->D0Epoch||!d->Completed||d->Completed!=d->Attempts||!d->LastSequence||d->LastSequence!=d->Attempts||!r||r->Epoch!=d->D0Epoch||r->Sequence!=d->LastSequence||r->Code||r->Uncertain||r->CancelledClean)return 0;
 S183_READING discarded;
 /* Re-execute the actual shipped structural/trace validator against the
  * quiesced same-epoch frame. Only its final battery-data semantic code7
  * qualifies; malformed/transport/policy/time/unknown faults still refuse. */
 return S183Validate(r,&discarded)==S183_DATA;
}
#endif
