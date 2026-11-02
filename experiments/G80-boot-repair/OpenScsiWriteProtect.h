// Exact four-byte MODE SENSE(6) response emitted by this Qualcomm MSD build.
// Return 1 when protected, 0 for another command, -1 for a malformed match.
// Base types are supplied by UEFI, or by the portable validation harness.
STATIC INTN
OpenProtectModeSense6 (CONST UINT8 *Cbw, UINTN CbwLength, UINT8 *Data, UINTN Length)
{
  UINT32 TransferLength;
  if (Cbw == NULL || CbwLength < 31) { return 0; }
  if (Cbw[0] != 'U' || Cbw[1] != 'S' || Cbw[2] != 'B' || Cbw[3] != 'C' ||
      Cbw[15] != 0x1a) { return 0; }
  TransferLength = (UINT32)Cbw[8] | ((UINT32)Cbw[9] << 8) |
    ((UINT32)Cbw[10] << 16) | ((UINT32)Cbw[11] << 24);
  if (Cbw[12] != 0x80 || Cbw[13] > 1 || Cbw[14] < 6 || Cbw[14] > 16 ||
      TransferLength < 4 || Cbw[19] < 4 || Data == NULL || Length != 4) { return -1; }
  if (Data[0] != 3 || Data[1] != 0 || (Data[2] & 0x7f) != 0 || Data[3] != 0) { return -1; }
  // MODE_PARAMETER_HEADER.DeviceSpecificParameter: MODE_DSP_WRITE_PROTECT.
  Data[2] |= 0x80;
  return 1;
}
