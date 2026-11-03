# G1347 — required timestamp output pointer

The G1345 hardware attempt stopped at a kernel access violation before producing a QTB result. Its new broker timer passed NULL to `KeQueryInterruptTimePrecise`. This was a software contract error, not a hardware translation result.

The genuine WDK header declares `_Out_ PULONG64 QpcTimeStamp`, without an optional annotation. [Microsoft documents](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kequeryinterrupttimeprecise) writable ULONG64 storage for the sampled performance counter. The return value remains interrupt time in100ns units.

G1347 changes only `QtbNow` in the broker include:

```c
ULONGLONG QpcTimestamp = 0;
return KeQueryInterruptTimePrecise(&QpcTimestamp) / 10;
```

The ignored context parameter and100ns-to-microsecond conversion are preserved. QTB encoding, deadlines, grants, lifetime checks, cleanup, fault handling and terminal-before-SQE behavior are unchanged. Existing per-file notices remain; no blanket license or OEM binary is supplied.

Run `python3 experiments/G1347/prepare.py --prepare --out /absolute/new/external/directory` to reconstruct the G1345 sources and apply this one-file overlay. It defaults to inert and performs no build or device action. Only the broker translation unit that includes the timer needs recompilation; the other14 broker COFF objects are reused exactly. Reuse the existing signed owner `a089ee59de66d26a009ec63eaf72a16e6f2dbb621ecc7734c0c17e8f70b82cc3` and firmware `328ffac3c14e885a355b7297747e6906430489c98eb0dc82ff4e5ed945923e8c`. No owner compile/sign or firmware rebuild is required.

The next intended phase is a fresh GPU-only terminal translation witness, with WLAN disabled and no repeated Wi-Fi trial. This source does not select that phase or supply future boot facts. Native link, independent compiled review and broker signing have passed; actual activation remains a separate step. See [validation](VALIDATION.md).
