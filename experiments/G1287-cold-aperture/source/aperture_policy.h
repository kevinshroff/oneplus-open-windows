#pragma once
/* Portable actual production classification; raw frame is never modified. */
typedef struct {unsigned long long X[8],Entries,Returns,Interrupted;} OAS_SCM_FRAME;
enum {OAS_SCM_UNKNOWN=0,OAS_SCM_TRANSPORT_COMPLETE=1,OAS_SCM_ERROR=2};
static inline int OasScmFrameValid(const OAS_SCM_FRAME*f){return f&&f->Returns&&f->Entries==f->Returns&&f->Interrupted==f->Returns-1;}
static inline unsigned OasScmTransport(const OAS_SCM_FRAME*f){
 if(!OasScmFrameValid(f))return OAS_SCM_UNKNOWN;
 if(f->X[0]==0)return OAS_SCM_TRANSPORT_COMPLETE;
 unsigned int lo=(unsigned int)f->X[0];unsigned long long hi=f->X[0]>>32;
 return (lo&0x80000000u)&&(hi==0||hi==0xffffffffULL)?OAS_SCM_ERROR:OAS_SCM_UNKNOWN;
}
/* Once any call was issued, failure (including postcheck) cannot use unpublished cleanup. */
static inline int OasSetupRetains(unsigned attempted,int success){return attempted&&!success;}
