/* Proposed supplementary namespace; does not replace the existing DSDT. */
DefinitionBlock ("", "SSDT", 2, "OPEN  ", "OPRES182", 0x00000001)
{
 Scope (\_SB)
 {
  Device (OPBM)
  {
   Name (_HID, "OPEN0182")
   Name (_UID, One)
   Name (_CCA, One)
   Name (_DDN, "OnePlus Open platform resources")
   Name (_STA, 0x0F)
   Name (_CRS, ResourceTemplate ()
   {
    Memory32Fixed (ReadOnly, 0x00152000, 0x00001000) // GCC votes
    Memory32Fixed (ReadOnly, 0x0011E000, 0x00001000) // primary root/branch clocks
    Memory32Fixed (ReadOnly, 0x00117000, 0x00001000) // secondary root/branch clocks
    Memory32Fixed (ReadOnly, 0x00123000, 0x00001000) // shared controller branch clocks
    Memory32Fixed (ReadOnly, 0x0F100000, 0x00001000) // primary SDA pin
    Memory32Fixed (ReadOnly, 0x0F101000, 0x00001000) // primary SCL pin
    Memory32Fixed (ReadOnly, 0x0F116000, 0x00001000) // secondary SDA pin
    Memory32Fixed (ReadOnly, 0x0F117000, 0x00001000) // secondary SCL pin
    Memory32Fixed (ReadWrite, 0x00880000, 0x00001000) // primary GENI I2C engine
    Memory32Fixed (ReadOnly, 0x008C0000, 0x00001000) // primary QUP wrapper
    Memory32Fixed (ReadWrite, 0x0098C000, 0x00001000) // secondary I2C hub engine
    Memory32Fixed (ReadOnly, 0x0C400000, 0x00001000) // SPMI arbiter identity
    Memory32Fixed (ReadOnly, 0x0C402000, 0x00001000) // SPMI APID map
    Memory32Fixed (ReadOnly, 0x0C42D000, 0x00001000) // SPMI APID owners
    Memory32Fixed (ReadWrite, 0x0C443000, 0x00001000) // fixed SPMI read-command pages A
    Memory32Fixed (ReadWrite, 0x0C445000, 0x00001000) // fixed SPMI read-command pages B
    Memory32Fixed (ReadOnly, 0x81A04000, 0x00010000) // pinned firmware FDT
    Memory32Fixed (ReadOnly, 0x81EFF000, 0x00001000) // SMEM TOC
    Memory32Fixed (ReadWrite, 0x81E9F000, 0x00060000) // AP/DSP SMEM partition
    Memory32Fixed (ReadWrite, 0x00408000, 0x00001000) // qualified IPCC doorbell page
   })
  }
 }
}
