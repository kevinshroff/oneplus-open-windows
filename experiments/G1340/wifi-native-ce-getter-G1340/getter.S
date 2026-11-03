.text
.p2align 2
.global body
// Offline getter source. No installation or runtime authorization.
// Body RVA14e09c; retain original prologue and exact epilogue14e1b4.
// Native HAL helper UNCHANGED. Its wake-failure vote retention remains known.
// Every failed query terminates the diagnostic sequence: no retries/next index.
// Symbolic RVA operands require module-relative relocation-aware assembly.
body:
 mov x20, x2
 cbz x20, fail
 mov w8, #0xce28
 cmp w0, w8
 b.ne fail
 cmp w1, #7
 b.hi fail
 adr x8, registers
 ldr w21, [x8, w1, uxtw #2]
 adrp x8, RVA_397000
 ldr w9, [x8, #0x738]
 cbnz w9, fail
 ldr x8, [x8, #0x728]
 cbz x8, fail
 ldr x8, [x8, #0x10]
 cbz x8, fail
 ldr x8, [x8, #0x10]
 cbz x8, fail
 ldr x8, [x8, #0xc8]
 cbz x8, fail
 add x8, x8, #0x37, lsl #12
 ldr x9, [x8, #0xf30]
 cbz x9, fail
 ldr x19, [x9, #0x440]
 cbz x19, fail
 ldr x8, [x19]
 cmp x8, x9
 b.ne fail
 add x8, x19, #7, lsl #12
 ldr w9, [x8, #0x73c]
 cmp w9, #1
 b.ne fail
 ldr w9, [x8, #0x750]
 cbnz w9, fail
 ldr w9, [x8, #0x7e4]
 str w9, [sp]
 mov x0, x19
 mov w1, w21
 bl RVA_1eb588
 mov w21, w0
 mov w8, #0xd
 movk w8, #0xc000, lsl #16
 cmp w21, w8
 b.eq fail
 cmn w21, #1
 b.eq fail
 cbz w21, fail
 add x8, x19, #7, lsl #12
 ldr w8, [x8, #0x7e4]
 ldr w9, [sp]
 cmp w8, w9
 b.ne fail
 str w21, [x20]
 mov w0, #0
 b ORIGINAL_EPILOGUE_14e1b4
fail:
 mov w0, #0x185
 movk w0, #0xc000, lsl #16
 b ORIGINAL_EPILOGUE_14e1b4
registers:
 .word 0x01b85400, 0x01b85404, 0x01b85408, 0x01b8540c
 .word 0x01b85010, 0x01b85014, 0x01b8506c, 0x01b85070
