Error classification correction, source-backed; no monitor call.

Actual installed QcTrEE_i primitive RVA1080 compares signed w0 after SMC (retained G1265 REA-actual-SIP-transport.snapshot.json / DESIGN.md). Primary pinned qcom_scm-smc.c486 passes smc_res.a0 to qcom_scm_remap_error; its declaration in qcom_scm.h243 takes int. Therefore a canonical zero-extended negative int32 cannot truthfully be labeled an unfinished positive token merely because x0 bit63 is clear. This is an error classification requirement; it does not prove which extension this target firmware actually returns.

G1268 now accepts negative low32 ONLY when upper32 is allzero or allones. It uses low32 to label busy(-12), unsupported(-1/-4), or raw other error. Raw x0..x7 are preserved. Noncanonical upper bits stay unknown/retained. Full64 x0==0 completion and full64 x0==1 interrupted continuation are unchanged; assembly/thunk bytes are unchanged. WAITQ2/3 still retain; no replay or fallback. No ABI/layout or IOCTL change.

Tests add four zero-extended errors and four malformed-upper-bit state cases; actual production thunk emulation adds three zero-extended errors and two malformed/noncanonical cases, checking return without continuation. 24 production state cases plus16 production thunk cases PASS. All SMC instructions were skipped before emulation; these are software tests only.
