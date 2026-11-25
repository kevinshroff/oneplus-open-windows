
.text
.p2align 2
.globl A740ArmCallSmc
.def A740ArmCallSmc; .scl 2; .type 32; .endef
.seh_proc A740ArmCallSmc
A740ArmCallSmc:
    stp x19, x20, [sp, #-32]!
    .seh_save_regp_x x19, 32
    stp x29, x30, [sp, #16]
    .seh_save_fplr 16
    add x29, sp, #16
    .seh_add_fp 16
    .seh_endprologue
    mov x19, x0
    ldp x0, x1, [x19, #0]
    ldp x2, x3, [x19, #16]
    ldp x4, x5, [x19, #32]
    ldp x6, x7, [x19, #48]
    smc #0
    stp x0, x1, [x19, #0]
    stp x2, x3, [x19, #16]
    stp x4, x5, [x19, #32]
    stp x6, x7, [x19, #48]
    .seh_startepilogue
    ldp x29, x30, [sp, #16]
    .seh_save_fplr 16
    ldp x19, x20, [sp], #32
    .seh_save_regp_x x19, 32
    .seh_endepilogue
    ret
    .seh_endproc
