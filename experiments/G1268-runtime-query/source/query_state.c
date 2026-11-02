#include "query_protocol.h"
void G1268Initialize(G1268_REPORT *R){
 unsigned char *B=(unsigned char *)R;unsigned int I;for(I=0;I<sizeof(*R);I++)B[I]=0;
 R->Magic=G1268_MAGIC;R->Version=G1268_VERSION;R->Bytes=sizeof(*R);R->State=G1268_IDLE;
 R->Input[0]=0xc2000601ULL;R->Input[1]=1;R->Input[2]=0x02000c1bULL;
}
int G1268Accept(G1268_REPORT *R){
 if(R->State!=G1268_IDLE||R->QueriesAccepted)return 0;
 R->QueriesAccepted=1;R->Flags|=G1268_F_ACCEPTED;R->State=G1268_QUEUED;return 1;
}
int G1268Begin(G1268_REPORT *R){
 if(R->State!=G1268_QUEUED||R->QueriesAccepted!=1)return 0;
 R->Flags|=G1268_F_THUNK_ENTERED;R->State=G1268_EXECUTING;return 1;
}
void G1268Finish(G1268_REPORT *R,const G1268_MONITOR_FRAME *M){
 unsigned int I;for(I=0;I<8;I++)R->Monitor.X[I]=M->X[I];
 R->Monitor.Entries=M->Entries;R->Monitor.Returns=M->Returns;R->Monitor.Interrupted=M->Interrupted;
 R->Flags|=G1268_F_THUNK_RETURNED;R->Availability=G1268_CAP_UNKNOWN;
 /* A mismatched frame or unfinished positive monitor state is never completion. */
 if(R->State!=G1268_EXECUTING||!M->Returns||M->Entries!=M->Returns||M->Interrupted!=M->Returns-1){goto retain;}
 G1268_U64 S=M->X[0];
 if(S==0){R->State=G1268_COMPLETE;R->Flags|=G1268_F_COMPLETION;R->Availability=M->X[1]?G1268_CAP_AVAILABLE:G1268_CAP_UNAVAILABLE;return;}
 /* Qualcomm errors are signed int32 (actual_i tests signed w0; primary remap_error(int)).
  * Accept only canonical zero/sign extension of a negative int32. Raw X[0] stays untouched.
  * Noncanonical upper bits are unknown, never fabricated completion/error/continuation. */
 G1268_U32 Lo=(G1268_U32)S;G1268_U64 Hi=S>>32;
 if((Lo&0x80000000U)&&(Hi==0||Hi==0xffffffffULL)){R->State=G1268_ERROR;if(Lo==0xfffffff4U)R->Flags|=G1268_F_BUSY;if(Lo==0xffffffffU||Lo==0xfffffffcU)R->Flags|=G1268_F_UNSUPPORTED;return;}
retain:R->State=G1268_INCOMPLETE_RETAINED;R->Flags|=G1268_F_RETAINED;
}
