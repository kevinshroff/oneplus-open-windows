DefinitionBlock ("", "SSDT", 2, "OPEN  ", "GPIOG21 ", 1)
{
    Name (G21C, 0x47323143)
    Scope (\_SB)
    {
        Device (GIO0)
        {
            Name (_HID, "QCOMFFEB")
            Name (_SUB, "MTP08550")
            Name (_UID, Zero)
            Name (_CCA, One)
            Name (GQCT, Zero)
            Name (GPCT, Zero)
            Name (GLST, Zero)
            Method (_STA, 0, NotSerialized) { Return (0x0F) }
            Name (RBUF, ResourceTemplate ()
            {
                Memory32Fixed (ReadWrite, 0x0F000000, 0x01000000)
                Interrupt (ResourceConsumer, Level, ActiveHigh, Shared) {240}
                Interrupt (ResourceConsumer, Level, ActiveHigh, Shared) {240}
                Interrupt (ResourceConsumer, Level, ActiveHigh, Shared) {240}
                Interrupt (ResourceConsumer, Level, ActiveHigh, Shared) {240}
                Interrupt (ResourceConsumer, Level, ActiveHigh, Shared) {569}
                Interrupt (ResourceConsumer, Level, ActiveHigh, Shared) {645}
            })
            Method (_CRS, 0, NotSerialized) { Return (RBUF) }
            Name (TMLM, Package (38)
            {
                    0x100000,
                    0x100004,
                    0x100008,
                    0x10000C,
                    0x3,
                    0x0,
                    0x3C,
                    0x2,
                    0x1C0,
                    0x6,
                    0x200,
                    0x9,
                    0x0,
                    0x0,
                    0x800,
                    0xB,
                    0x1000,
                    0xC,
                    0x0,
                    0x0,
                    0x1,
                    0x0,
                    0x2,
                    0x1,
                    0x1,
                    0x0,
                    0x2,
                    0x1,
                    0xC,
                    0x2,
                    0x10,
                    0x4,
                    0xE0,
                    0x5,
                    0x0,
                    0x0,
                    0x1,
                    0x0
            })
            Name (WPDC, Package (2)
            {
                Package (3) {57, 25, 569},
                Package (3) {98, 174, 645}
            })
            Method (_DSM, 4, Serialized)
            {
                If (Arg1 != Zero) { Return (Buffer (1) {0}) }
                If (Arg0 == ToUUID ("98b9b2a4-1663-4a5f-82f2-c6c99a394726"))
                {
                    Increment (GQCT)
                    Store (Arg2, GLST)
                    Switch (ToInteger (Arg2))
                    {
                        Case (0) { Return (Buffer (1) {0x3F}) }
                        Case (1) { Return (Zero) }
                        Case (2) { Return (210) }
                        Case (3) { Return (0x1000) }
                        Case (4) { Return (TMLM) }
                        Case (5) { Return (Zero) }
                    }
                }
                If (Arg0 == ToUUID ("921b0fd4-567c-43a0-bb14-2648f7b2a18c"))
                {
                    Increment (GPCT)
                    Store (Arg2, GLST)
                    Switch (ToInteger (Arg2))
                    {
                        Case (0) { Return (Buffer (1) {0x3F}) }
                        Case (1) { Return (One) }
                        Case (2) { Return (WPDC) }
                        Case (3) { Return (0x0B220010) }
                        Case (4) { Return (0x0B220110) }
                        Case (5) { Return (0x4330) }
                    }
                }
                Return (Buffer (1) {0})
            }
        }
    }
}
