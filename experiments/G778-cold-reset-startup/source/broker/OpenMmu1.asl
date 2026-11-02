// Coherent source publisher input; no boot image or native publication selected.
// Dedicated Open GPU SMMU + its exact S0 clock lease resources. No Apps SMMU.
// OPEN0D01 binds ONLY the source-owned adapter, never unmodified QCOM0C09.
// No152000 descriptor: active OPBM supplies fixed parent reads via interface.
// Future GPU0 must exclude GPUCC/GCC and use this broker. Secure/HAL alias
// admission remains to be established before publication.
// Future coherent IRQ publication: global705 + allocator bootstrap CB2 IRQ711.
// Requires corrected IORT context LEVEL flags; no firmware installed here.
DefinitionBlock ("", "SSDT", 2, "OPEN  ", "OMMUGMU ", 1)
{
    External (\_SB.OPBM, DeviceObj)
    Scope (\_SB)
    {
        Device (MMU1)
        {
            Name (_HID, "OPEN0D01")
            Name (_UID, One)
            Name (_DEP, Package () { \_SB.OPBM })
            Name (_DDN, "Open SM8550 dedicated GPU SMMU clock lease")
            Method (_STA, 0, NotSerialized) { Return (0x0F) }
            Name (_CRS, ResourceTemplate ()
            {
                Memory32Fixed (ReadWrite, 0x03DA0000, 0x00040000, SMRG)
                Memory32Fixed (ReadWrite, 0x03D97000, 0x00001000, SMCK)
                Memory32Fixed (ReadWrite, 0x03D99000, 0x00001000, GPCK)
                Memory32Fixed (ReadWrite, 0x00171000, 0x00001000, GCCK)
                Memory32Fixed (ReadOnly,  0x00100000, 0x00001000, GPLL)
                Memory32Fixed (ReadOnly,  0x03D91000, 0x00001000, PLL1)
                Interrupt (ResourceConsumer, Level, ActiveHigh, Exclusive, ,, GLBL) { 705 }
                Interrupt (ResourceConsumer, Level, ActiveHigh, Exclusive, ,, CB02) { 711 }
            })
        }
    }
}
