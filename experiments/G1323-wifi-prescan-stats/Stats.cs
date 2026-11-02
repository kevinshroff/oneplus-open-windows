using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;

// Inert library: loading/compiling this file invokes no WLAN operation.
// Root must embed it inside the freshly admitted, once-only original-init/scan task.
public static class PreScanStatsOnce
{
    private static int consumed;
    private const uint StatisticsOpcode = 0x10000101;
    [DllImport("C:\\Windows\\System32\\wlanapi.dll", ExactSpelling = true)]
    private static extern uint WlanOpenHandle(uint version, IntPtr reserved,
        out uint negotiatedVersion, out IntPtr handle);
    [DllImport("C:\\Windows\\System32\\wlanapi.dll", ExactSpelling = true)]
    private static extern uint WlanQueryInterface(IntPtr handle, ref Guid id,
        uint opcode, IntPtr reserved, out uint size, out IntPtr data, out uint valueType);
    [DllImport("C:\\Windows\\System32\\wlanapi.dll", ExactSpelling = true)]
    private static extern void WlanFreeMemory(IntPtr data);
    [DllImport("C:\\Windows\\System32\\wlanapi.dll", ExactSpelling = true)]
    private static extern uint WlanCloseHandle(IntPtr handle, IntPtr reserved);

    public static object Run(Guid selectedInterface, bool rootAdmittedBeforeSoleScan)
    {
        if (!rootAdmittedBeforeSoleScan || selectedInterface == Guid.Empty || IntPtr.Size != 8)
            throw new InvalidOperationException("Fresh root admission and selected native64 interface required");
        if (Interlocked.Exchange(ref consumed, 1) != 0)
            throw new InvalidOperationException("Statistics probe already consumed in this process; no retry");
        IntPtr handle = IntPtr.Zero, data = IntPtr.Zero;
        uint negotiated, size = 0, valueType = 0;
        uint opened = WlanOpenHandle(2, IntPtr.Zero, out negotiated, out handle);
        if (opened != 0)
            return new { openResult = opened, queryRequests = 0, firmwareProgressEstablished = false };
        try
        {
            DateTimeOffset begin = DateTimeOffset.UtcNow;
            Stopwatch elapsed = Stopwatch.StartNew();
            // Exactly one supported query. It may block inside Windows; never replay on timeout.
            uint status = WlanQueryInterface(handle, ref selectedInterface, StatisticsOpcode,
                IntPtr.Zero, out size, out data, out valueType);
            elapsed.Stop();
            return new { openResult = opened, queryResult = status, queryRequests = 1,
                beginUtc = begin.ToString("o"), endUtc = DateTimeOffset.UtcNow.ToString("o"),
                elapsedMilliseconds = elapsed.Elapsed.TotalMilliseconds,
                returnedBytes = size, returnedPointerNonzero = data != IntPtr.Zero,
                opcode = StatisticsOpcode, valueType = valueType,
                firmwareProgressEstablished = false,
                requiresActualWdi16001RxAndCreditLogCorrelation = true };
        }
        finally
        {
            if (data != IntPtr.Zero) WlanFreeMemory(data);
            WlanCloseHandle(handle, IntPtr.Zero);
        }
    }
}
