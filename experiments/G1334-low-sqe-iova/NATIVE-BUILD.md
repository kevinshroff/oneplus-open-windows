# Actual native link and targeted compiled review

The 35-object G1334 owner closure subsequently linked successfully with native
Microsoft MSVC, exit 0. Unsigned ARM64 `OpenGpuStart.sys` is 134,656 bytes,
SHA256 `459c50201ebd54dd911150e6da060f8517333b1f02aedb46724f9c02f75867ce`.
It is a native-subsystem PE, entry RVA `0x1060`, with imports from ntoskrnl and
HAL. The source-preparation results in README/VALIDATION precede this link.

Targeted Ghidra 12.1.4 REA review of this exact SYS observed the selected tuple
in linked data and its use by Prepare, the dynamic sorted table allocator,
the original guarded SQE release and normal CP sequence, actual shadow-fence
loads and completion checks, and retained-owner/closed-entry behavior.
Five table pages and 29 leaves are derived from the compiled allocator and
selected tuple; no live G1334 allocation is asserted. The review covered these
paths, not every function in all 35 objects. Original default-off COFF parity
and the isolated one-object change remain the change-coverage evidence.

The private review exports 14 Evidence records; its bundle SHA256 is
`d6d49c2f509d4e8bbca739e13f8180c9b931f8e90a643787362106de2635e750`.
REA was exported and closed. Native linking and static review do not prove
hardware fetch, a real GPU fence, acceleration, current-boot admission or a
successful driver load. No reviewer signing, staging, loading or hardware
operation occurred. The WDDM provider remains closed.
