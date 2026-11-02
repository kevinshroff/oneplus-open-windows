// Coherent replacement GPU0 source; never append beside an existing GPU0.
// Consumed by the real reviewed five-bank G482 binder in this owner.
// Clock-control holes and GCC page belong solely to MMU1 broker; no IRQ/DMA.
DefinitionBlock ("", "SSDT", 2, "OPEN  ", "GPUSPLIT", 1)
{
 External (\_SB.MMU1, DeviceObj)
 Scope (\_SB) { Device (GPU0) {
  Name (_HID, "OPEN0515")
  Name (_UID, Zero)
  Name (_DEP, Package () { \_SB.MMU1 })
  Name (_STA, 0x0F)
  Name (_CRS, ResourceTemplate () {
   Memory32Fixed (ReadWrite, 0x03D00000, 0x00040000)
   Memory32Fixed (ReadWrite, 0x03D50000, 0x00010000)
   Memory32Fixed (ReadWrite, 0x03D68000, 0x00028000)
   Memory32Fixed (ReadWrite, 0x03D9A000, 0x00005000)
   Memory32Fixed (ReadWrite, 0x0B280000, 0x00010000)
  })
 } }
}
