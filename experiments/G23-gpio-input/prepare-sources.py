"""Derive a RAM-only GPIO input diagnostic from the qualified G21 namespace.

No native writes. Preserve the exact G22 development driver in the WIM.
The GPIO inputs are the two source-correlated touch IRQ lines, not rail/reset
outputs. Windows will configure their input connection; this is not a claim
that the controller callback leaves pin-control registers unchanged.
"""
from pathlib import Path
import hashlib, json

W = Path(__file__).resolve().parent
source = W.parent / 'gpio-G21/build-controller-table.py'
text = source.read_text().replace('G21', 'G23')
text = text.replace('0x47323143', '0x47323343')
text = text.replace("struct.unpack_from('<I', b, 24)[0] + 2", "struct.unpack_from('<I', b, 24)[0] + 4")
text = text.replace('Name (_CCA, One)', r'''Name (_CCA, One)
            Name (GRDY, Zero)
            Name (GRCT, Zero)
            Name (STCT, Zero)
            Name (RCNT, Zero)
            Name (R025, 0xFF)
            Name (R174, 0xFF)
            OperationRegion (GPR0, GeneralPurposeIo, Zero, One)
            Field (GPR0, ByteAcc, NoLock, Preserve)
            {
                Connection (GpioIo (Exclusive, PullDefault, 0, 0,
                    IoRestrictionInputOnly, "\\\\_SB.GIO0", 0,
                    ResourceConsumer, , ) {25}),
                GP25, 1,
                Connection (GpioIo (Exclusive, PullDefault, 0, 0,
                    IoRestrictionInputOnly, "\\\\_SB.GIO0", 0,
                    ResourceConsumer, , ) {174}),
                GP74, 1
            }
            Method (_REG, 2, Serialized)
            {
                If (Arg0 == 8)
                {
                    Store (Arg1, GRDY)
                    Increment (GRCT)
                }
            }
            Method (RDP0, 0, Serialized)
            {
                If (GRDY != One) { Return (0xBAD00008) }
                Store (GP25, R025)
                Increment (RCNT)
                Return (R025)
            }
            Method (RDP1, 0, Serialized)
            {
                If (GRDY != One) { Return (0xBAD00008) }
                Store (GP74, R174)
                Increment (RCNT)
                Return (R174)
            }''')
text = text.replace('Method (_STA, 0, NotSerialized) { Return (0x0F) }', '''Method (_STA, 0, Serialized)
            {
                Increment (STCT)
                If (GRDY == One)
                {
                    RDP0 ()
                    RDP1 ()
                }
                Return (0x0F)
            }''')
text = text.replace("'phase': 'offline_GPIO_controller_trial_not_yet_booted'", "'phase': 'offline_GPIO_input_trial_not_yet_booted'")
text = text.replace("'scope': 'First controller binding trial with two real touch wake channels and no peripheral children. Remaining wake channels and all hardware goals remain open.'", "'scope': 'RAM-only GeneralPurposeIo reads on physical touch IRQ pins25/174 after handler availability; _STA invokes diagnostic reads only while GRDY=1. No rail/reset outputs or interrupts requested.'")
target = W / 'build-input-table.py'
assert not target.exists()
target.write_text(text)
receipt = {'source': str(source), 'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
           'output': str(target), 'output_sha256': hashlib.sha256(target.read_bytes()).hexdigest(),
           'current_physical_session': '00000000000000000000000000000000',
           'GPIO_callbacks_unchanged_from_G22': True,
           'native_trigger': 'diagnostic _STA after GRDY becomes1, including PnP rescan',
           'hardware_write_scope': 'ConnectIoPins may configure input pull/mux/OE/EGPIO for25/174; no GPIO output requests or latch writes',
           'references': ['https://learn.microsoft.com/en-us/windows-hardware/drivers/bringup/general-purpose-i-o--gpio-',
                          'https://uefi.org/specs/ACPI/6.5/05_ACPI_Software_Programming_Model.html',
                          'https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/gpioclx/ns-gpioclx-_gpio_connect_io_pins_parameters']}
(W / 'source-derivation.json').write_text(json.dumps(receipt, indent=2) + '\n')
print(json.dumps(receipt, indent=2))
