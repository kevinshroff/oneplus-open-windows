# G1348: use the existing CB0 write mapping

G1347 reached the QTB callback but faulted on a CPU store through the broker’s broad read-only SMMU mapping. No QTB translation result was obtained. This candidate redirects only the temporary CB0 SCTLR write and its original-value restoration to the fault owner’s existing read-write, noncached CB0 page.

The broker captures `Fault.Map[2]` while holding its existing lock and requires the same nonnull pointer, bank, and generation during admission and immutable cleanup. The fault owner already maps physical `0x03dc0000` for one page with `PAGE_READWRITE|PAGE_NOCACHE`. No mapping or page protection is changed. Broad SMMU reads retain their original read-only mapping. Cleanup does not require an interrupt to remain armed: retained fault cleanup still requires the captured mapping and all existing lifetime authority.

The valid local QPC-output correction from G1347 remains. Owner, firmware, ABI7, core witness protocol, interrupt ownership, and all other sources are unchanged. The subsequent [hardware result](HARDWARE-RESULT.md) matched the expected MDL page and confirmed control restoration. Command execution and WDDM remain the next milestones.

Run `python3 experiments/G1348/prepare.py --prepare --out /fresh/external/source-tree` for an explicit source overlay. Default invocation is inert; output must be new and outside this checkout. `test_cb0_write_authority.py` exercises the actual cleanup and write callbacks with host stubs; it does not access a kernel or device.
