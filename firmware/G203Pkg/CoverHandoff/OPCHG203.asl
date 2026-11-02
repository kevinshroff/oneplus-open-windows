/* Separate report only; no framebuffer or OPRES182 resource. */
DefinitionBlock ("", "SSDT", 2, "OPEN  ", "OPCHG203", 1)
{
 Scope (\_SB) { Device (OPCH) {
  Name (_HID, "OPEN0203")
  Name (_UID, One)
  Name (_CCA, One)
  Name (_DDN, "OnePlus Open bounded cover clear report")
  Name (_STA, 0x0F)
  Name (_CRS, ResourceTemplate () {
   Memory32Fixed (ReadOnly, 0xDEAD0000, 0x00031000)
  })
 } }
}
