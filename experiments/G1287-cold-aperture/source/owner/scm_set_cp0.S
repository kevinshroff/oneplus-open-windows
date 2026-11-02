/* Fixed NORMAL64 CP0 aperture setter, four VALUE arguments only.
 * No FAST/HVC/legacy/buffer fallback. Preserve raw returned x0..x7 and x6 continuation.
 * A positive state other than exact INTERRUPTED1 returns to sticky-retain policy. */
.text
.p2align 2
.globl G1287SmcSetCp0
.def G1287SmcSetCp0; .scl 2; .type 32; .endef
.seh_proc G1287SmcSetCp0
G1287SmcSetCp0:
 stp x19,x20,[sp,#-32]!
 .seh_save_regp_x x19,32
 stp x29,x30,[sp,#16]
 .seh_save_fplr 16
 add x29,sp,#16
 .seh_add_fp 16
 .seh_endprologue
 mov x19,x0
 movz x0,#0x0c1b
 movk x0,#0x4200,lsl #16
 mov x1,#4
 movz x2,#0
 movk x2,#0xffff,lsl #16
 mov w3,#0xffffffff
 mov w4,#0xffffffff
 mov w5,#0xffffffff
 mov x6,xzr
 mov x7,xzr
.Lenter:
 ldr x9,[x19,#64]
 cmn x9,#1
 b.eq .Lissue
 add x9,x9,#1
 str x9,[x19,#64]
.Lissue:
 smc #0
 stp x0,x1,[x19]
 stp x2,x3,[x19,#16]
 stp x4,x5,[x19,#32]
 stp x6,x7,[x19,#48]
 ldr x9,[x19,#72]
 cmn x9,#1
 b.eq .Lclassify
 add x9,x9,#1
 str x9,[x19,#72]
.Lclassify:
 cmp x0,#1
 b.ne .Lreturn
 ldr x9,[x19,#80]
 cmn x9,#1
 b.eq .Lenter
 add x9,x9,#1
 str x9,[x19,#80]
 b .Lenter
.Lreturn:
 .seh_startepilogue
 ldp x29,x30,[sp,#16]
 .seh_save_fplr 16
 ldp x19,x20,[sp],#32
 .seh_save_regp_x x19,32
 .seh_endepilogue
 ret
 .seh_endproc
