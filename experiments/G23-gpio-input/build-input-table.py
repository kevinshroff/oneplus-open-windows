"""Build the first real GPIO-controller trial; do not deploy from this script."""
from pathlib import Path
import hashlib
import json
import struct
import subprocess

W = Path(__file__).resolve().parent
P = W / 'private'
P.mkdir(exist_ok=True)
original = W.parent / 'acpi-G20/private/DSDT-native.bin'
b = original.read_bytes()
assert hashlib.sha256(b).hexdigest() == 'c8ef19940f424fce18a6e56580493629accb7c59a9ae495cc42c9445029f3e01'
assert b[:4] == b'DSDT' and len(b) == 576 and sum(b) % 256 == 0
layout = json.loads((W.parent / 'gpio-G19/contract-layout.json').read_text())
registers = json.loads((W.parent / 'gpio-G20/register-contract.json').read_text())
fields = {}
for r in registers['register_offsets']:
    fields[int(r['context_offset'], 16)] = int(r['vendor_value'], 16)
for r in registers['bit_fields']:
    fields[int(r['mask_context'], 16)] = int(r['vendor_mask'], 16)
    fields[int(r['shift_context'], 16)] = r['vendor_shift']
# These six copied slots have no observed controller-context consumers in
# the audited recovered procedures of this exact driver. Zero is a trial
# reservation, not a reconstructed hardware bit definition or a general ABI.
reserved = [0x68, 0x6c, 0x80, 0x84, 0xc0, 0xc4]
assert set(fields).isdisjoint(reserved)
fields.update({o: 0 for o in reserved})
offsets = [int(x['offset'], 16) for x in layout['selector4_layout_variants']['0']['argument_to_context_offset']]
assert len(offsets) == 38 and set(offsets) == set(fields)
values = [fields[o] for o in offsets]
pkg = ',\n                    '.join('0x%X' % x for x in values)
asl = '''DefinitionBlock ("", "SSDT", 2, "OPEN  ", "GPIOG23 ", 1)
{
    Name (G23C, 0x47323343)
    Scope (\\_SB)
    {
        Device (GIO0)
        {
            Name (_HID, "QCOMFFEB")
            Name (_SUB, "MTP08550")
            Name (_UID, Zero)
            Name (_CCA, One)
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
            }
            Name (GQCT, Zero)
            Name (GPCT, Zero)
            Name (GLST, Zero)
            Method (_STA, 0, Serialized)
            {
                Increment (STCT)
                If (GRDY == One)
                {
                    RDP0 ()
                    RDP1 ()
                }
                Return (0x0F)
            }
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
                    %s
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
''' % pkg
dsl = P / 'gpio-controller.dsl'
assert not dsl.exists()
dsl.write_text(asl)
subprocess.run(['iasl', '-tc', str(dsl)], check=True)
payload = dsl.with_suffix('.aml').read_bytes()
assert sum(payload) % 256 == 0 and payload[:4] == b'SSDT'
# The compiled driver's SOSI scanner reads an eight-byte value at name+5,
# without interpreting AML integer width. Preserve the original QWordConst.
needle = b'\x08SOSI\x0e' + struct.pack('<Q', 0xDEADBEEFFFFFFFFF)
assert b.count(needle) == 1
index = b.index(needle) + 6
a = bytearray(b)
a[index:index+8] = struct.pack('<Q', 0x81d08408)
assert a[index-1] == 0x0e
a.extend(payload[36:])
struct.pack_into('<I', a, 4, len(a))
struct.pack_into('<I', a, 24, struct.unpack_from('<I', b, 24)[0] + 4)
a[9] = 0
a[9] = (-sum(a)) & 255
assert sum(a) % 256 == 0
out = P / 'acpitabl.dat'
assert not out.exists()
out.write_bytes(a)
receipt = {
    'phase': 'offline_GPIO_input_trial_not_yet_booted',
    'source_DSDT_sha256': hashlib.sha256(b).hexdigest(),
    'candidate_DSDT_sha256': hashlib.sha256(a).hexdigest(),
    'candidate_bytes': len(a),
    'existing_AML_change': {'name': 'SOSI', 'value_byte_offset': index,
                            'before': '0xDEADBEEFFFFFFFFF', 'after': '0x81d08408',
                            'QWordConst_prefix_preserved': True},
    'primary_layout': 0,
    'direct_uniform_GPIO_count': 210,
    'excluded_nonuniform_pin': 210,
    'selector4_values': [{'argument': i, 'context_offset': hex(o), 'value': fields[o]}
                         for i, o in enumerate(offsets)],
    'trial_reserved_zero_slots': [hex(x) for x in reserved],
    'reserved_limit': 'No hardware meaning assigned; audited binary only, live controller context must be checked.',
    'PDC_native_version': '0x00030000',
    'PDC_mode': 1,
    'PDC_selector5': '0x4330',
    'PDC_nibbles': {'unused_n0': 0, 'preserved_low_nibble_bit': 3,
                    'mask_bit': 3, 'status_bit': 4},
    'initial_wake_channels': [{'TLMM': 25, 'PDC': 57, 'GSI': 569, 'virtual_pin': 256},
                              {'TLMM': 174, 'PDC': 98, 'GSI': 645, 'virtual_pin': 320}],
    'scope': 'RAM-only GeneralPurposeIo reads on physical touch IRQ pins25/174 after handler availability; _STA invokes diagnostic reads only while GRDY=1. No rail/reset outputs or interrupts requested.',
    'driver_sha256': registers['binary_sha256'],
    'raw_phone_writes': 0,
}
(W / 'controller-table-candidate.json').write_text(json.dumps(receipt, indent=2) + '\n')
print(json.dumps({k: receipt[k] for k in ['phase', 'candidate_DSDT_sha256', 'candidate_bytes']}))
