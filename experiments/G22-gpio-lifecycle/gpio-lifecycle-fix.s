// RAM-only development fix for exact qcgpio_i.sys SHA 3e048697...d50700.
// Numeric ADRP operands in this assembler are page deltas, not target RVAs.
// All code stays inside the existing functions and their unwind coverage.
.text
.org 0x2a8c
pin_owner_output:
    add x5, x23, #0xe0       // WDFMEMORY*, new tail of controller context.

.org 0x2cac
release_pin_owner:
    ldr x1, [x19, #0xe0]   // Delete the object, never its borrowed buffer.
    cbz x1, clear_pin_owner
    adrp x8, 0xb000        // Current page 0x2000 -> globals page 0xd000.
    ldr x9, [x8, #0x358]   // WDF function table.
    ldr x0, [x8, #0x388]   // WDF_DRIVER_GLOBALS*.
    ldr x15, [x9, #0x680]  // WdfObjectDelete, table index 208.
    adrp x17, 0xa000       // Current page 0x2000 -> IAT page 0xc000.
    ldr x17, [x17, #0x118] // Preserve the artifact's indirect-call guard.
    blr x17
    blr x15
clear_pin_owner:
    str xzr, [x19, #0x30]
    str xzr, [x19, #0xe0]
    b release_trace_base
    .rept 6
    nop
    .endr
release_trace_base:
    adrp x24, 0xa000       // Retain downstream trace-string base setup.
    // Continues at original 0x2cfc: PDC MMIO unmapping/reset logic.

.org 0x8020
zero_pdc_records:
    cbz x9, pdc_allocation_failure
    mov x0, x9
    ldr w8, [x23, #4]      // Exact count from firmware, no padded records.
    mov x2, #0x30
    mul x2, x8, x2
    mov w1, #0
    bl driver_memset
    ldr x9, [x26, #0x38]   // Restore volatile table pointer after memset.
    b pdc_parse_records
    nop
    nop
    nop
    nop
    nop
pdc_parse_records:
    // Continues at original 0x8058; initializes IDs and virtual assignments.

// Labels only. These define existing destinations, with no replacement bytes.
.set pdc_allocation_failure, zero_pdc_records - (0x8020 - 0x7d94)
.org 0xa200
driver_memset:

.org 0x10180
controller_context_size:
    mov w8, #0xe8         // Original 0xe0 bytes + one eight-byte owner handle.
