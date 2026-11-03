// Offline code seam only. Exact G1346 no-hint baseline is mandatory.
// Enter at original STP W28,W8,[X19,#0x10]. Preserve W8, W28 and NZCV.
// W9 is dead until its existing AND definition at RVA1d778c.
.text
.globl priority_body
priority_body:
  eor w9, w28, #1
  clz w9, w9
  lsr w9, w9, #5
  add w9, w28, w9
  stp w9, w8, [x19, #0x10]
// Offline patch recipe appends B RVA1d7760 at actual cave RVA1d7c38.
