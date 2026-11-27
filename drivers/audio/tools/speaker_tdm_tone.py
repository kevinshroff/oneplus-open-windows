# Speaker bring-up test (lab harness): opens WR_SHARED_MEM_EP -> GAIN -> TDM_SINK on Secondary TDM, powers the three
# TFA9873 amps and streams a quiet 440 Hz tone through OpenChargerKeeper (v24+). Runs a PowerShell/C# payload on the
# phone through the project lab queue (maintenance/lab.py). Tone level -31 dBFS.
import sys
import os
sys.path.insert(0, os.environ.get('LAB_MAINTENANCE_DIR', 'maintenance'))
import lab

ps = r'''
$code = @"
using System;
using System.IO;
using System.Runtime.InteropServices;

public class AudioTdm {
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    static extern IntPtr CreateFile(string fn, uint acc, uint share, IntPtr sec, uint disp, uint flags, IntPtr tmpl);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool DeviceIoControl(IntPtr h, uint code, byte[] inB, int inS, byte[] outB, int outS, out int ret, IntPtr ov);
    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr h);

    static byte[] Ioctl(IntPtr h, uint code, byte[] inp, int outSz) {
        byte[] outb = new byte[Math.Max(outSz, 8192)];
        int ret = 0;
        bool ok = DeviceIoControl(h, code, inp, inp == null ? 0 : inp.Length, outb, outb.Length, out ret, IntPtr.Zero);
        if (!ok) throw new Exception("IOCTL 0x" + code.ToString("X8") + " failed err=" + Marshal.GetLastWin32Error());
        int cp = Math.Min(ret, outSz > 0 ? Math.Max(outSz, 4) : 0);
        byte[] res = new byte[cp];
        Array.Copy(outb, res, cp);
        return res;
    }

    static uint SendGpr(IntPtr h, string label, uint dstPort, uint opcode, uint tok, byte[] apmPayload) {
        int tot = 24 + 16 + apmPayload.Length;
        byte[] pkt = new byte[tot];
        BitConverter.GetBytes((uint)((6 << 4) | (tot << 8))).CopyTo(pkt, 0);
        BitConverter.GetBytes((uint)(2 | (3 << 8))).CopyTo(pkt, 4);
        BitConverter.GetBytes(0x2001u).CopyTo(pkt, 8);
        BitConverter.GetBytes(dstPort).CopyTo(pkt, 12);
        BitConverter.GetBytes(tok).CopyTo(pkt, 16);
        BitConverter.GetBytes(opcode).CopyTo(pkt, 20);
        BitConverter.GetBytes((uint)apmPayload.Length).CopyTo(pkt, 36);
        Array.Copy(apmPayload, 0, pkt, 40, apmPayload.Length);
        Ioctl(h, 0x0022A028u, pkt, 4);
        for (int t = 0; t < 20; t++) {
            System.Threading.Thread.Sleep(35);
            byte[] rx = Ioctl(h, 0x0022602Cu, null, 256);
            if (rx.Length >= 32) {
                uint st = BitConverter.ToUInt32(rx, 28);
                Console.WriteLine(string.Format("{0}: status=0x{1:X}", label, st));
                return st;
            }
        }
        Console.WriteLine(label + ": TIMEOUT");
        return 0xFFFFFFFFu;
    }

    static string Probe() {
        var psi = new System.Diagnostics.ProcessStartInfo("sc.exe", "start tlmmprobe"); psi.UseShellExecute = false; psi.RedirectStandardOutput = true; psi.CreateNoWindow = true;
        var pr = System.Diagnostics.Process.Start(psi); pr.StandardOutput.ReadToEnd(); pr.WaitForExit();
        System.Threading.Thread.Sleep(150);
        string r = "";
        foreach (string line in System.IO.File.ReadAllLines(@"C:\topaz\tlmmprobe.log")) {
            int g = line.IndexOf("gpio "); int t = line.IndexOf("transitions ");
            if (g >= 0 && t >= 0) r += line.Substring(g + 5, 3) + ":" + line.Substring(t + 12).Trim() + " ";
        }
        return r;
    }
    static uint TfaCmd(IntPtr h, uint op, uint addr, uint reg, uint val) {
        byte[] req = new byte[16];
        BitConverter.GetBytes(op).CopyTo(req, 0);
        BitConverter.GetBytes(addr).CopyTo(req, 4);
        BitConverter.GetBytes(reg).CopyTo(req, 8);
        BitConverter.GetBytes(val).CopyTo(req, 12);
        byte[] rsp = Ioctl(h, 0x0022E030u, req, 64);
        return BitConverter.ToUInt32(rsp, 4);
    }

    static void W32(MemoryStream ms, uint v) { byte[] b = BitConverter.GetBytes(v); ms.Write(b, 0, 4); }
    static void W16(MemoryStream ms, ushort v) { byte[] b = BitConverter.GetBytes(v); ms.Write(b, 0, 2); }
    static void Pad8(MemoryStream ms) { while ((ms.Position % 8) != 0) ms.WriteByte(0); }
    static void PHdr(MemoryStream ms, uint iid, uint pid, uint sz) { W32(ms, iid); W32(ms, pid); W32(ms, sz); W32(ms, 0u); }

    public static void Run() {
        byte[] sgList0; { MemoryStream sl0 = new MemoryStream(); PHdr(sl0, 1u, 0x08001005u, 12u); W32(sl0, 2u); W32(sl0, 0x4001u); W32(sl0, 0x4002u); Pad8(sl0); sgList0 = sl0.ToArray(); }
        IntPtr h = CreateFile(@"\\.\OpenChargerKeeper", 0xC0000000u, 3, IntPtr.Zero, 3, 0, IntPtr.Zero);
        if (h == (IntPtr)(-1)) { Console.WriteLine("Open failed " + Marshal.GetLastWin32Error()); return; }
        for (int i = 0; i < 8; i++) { if (Ioctl(h, 0x0022602Cu, null, 256).Length == 0) break; }

        { MemoryStream sl = new MemoryStream(); PHdr(sl, 1u, 0x08001005u, 12u); W32(sl, 2u); W32(sl, 0x4001u); W32(sl, 0x4002u); Pad8(sl);
          SendGpr(h, "PRE_STOP", 1u, 0x01001003u, 0x0F1, sl.ToArray()); SendGpr(h, "PRE_CLOSE", 1u, 0x01001004u, 0x0F2, sl.ToArray()); }
        for (int i = 0; i < 8; i++) { if (Ioctl(h, 0x0022602Cu, null, 256).Length == 0) break; }
        // 1. Stage-1 SMMU (Op=2: IOVA 0x10000000 -> FrpcPhys) for 0x1001/0x80 and 0x1061/0
        uint[,] sids = new uint[,] { {0x1001, 0x80}, {0x1061, 0} };
        for (int i = 0; i < 2; i++) {
            byte[] req = new byte[12];
            BitConverter.GetBytes(2u).CopyTo(req, 0);
            BitConverter.GetBytes(sids[i,0]).CopyTo(req, 4);
            BitConverter.GetBytes(sids[i,1]).CopyTo(req, 8);
            byte[] rsp = Ioctl(h, 0x0022E038u, req, 256);
            Console.WriteLine(string.Format("SMMU_S1 0x{0:X4}/0x{1:X4}: st={2} cb={3} sctlr=0x{4:X}",
                sids[i,0], sids[i,1], BitConverter.ToUInt32(rsp,0), BitConverter.ToUInt32(rsp,36), BitConverter.ToUInt32(rsp,52)));
        }

        // 2. HYP_ASSIGN FrpcBuf -> {3, 5}
        byte[] hreq = new byte[8]; BitConverter.GetBytes(5u).CopyTo(hreq, 0);
        byte[] hrsp = Ioctl(h, 0x0022E03Cu, hreq, 64);
        uint bufSize = BitConverter.ToUInt32(hrsp, 40);
        Console.WriteLine(string.Format("HYP(05): R0={0} R1={1} phys=0x{2:X}", BitConverter.ToInt64(hrsp,0), BitConverter.ToInt64(hrsp,8), BitConverter.ToUInt64(hrsp,32)));

        // 3. Mux GPIO 121..124 + PRM LPASS + 3.072 MHz SEC_MI2S_IBIT (0x102)
        TfaCmd(h, 1, 0x34, 0, 0);
        { MemoryStream ms = new MemoryStream(); PHdr(ms, 2u, 0x08001032u, 4u); W32(ms, 1u); SendGpr(h, "PRM_LPASS", 2u, 0x0100100Fu, 0x101, ms.ToArray()); }
        { MemoryStream ms = new MemoryStream(); PHdr(ms, 2u, 0x0800102Cu, 20u); W32(ms, 1u); W32(ms, 0x202u); W32(ms, 3072000u); W32(ms, 1u); W32(ms, 0u); SendGpr(h, "PRM_TDM2_3M072", 2u, 0x0100100Fu, 0x102, ms.ToArray()); }

        // 4. Open MATCHED 32-bit 48kHz stereo graph: WR_SH_MEM_EP -> GAIN -> I2S_SINK (LPAIF=5, intf=1, SD1=2)
        uint SG1 = 0x4001u, SG2 = 0x4002u, CT1 = 0x4101u, CT2 = 0x4102u;
        uint M_EP = 0x4201u, M_GN = 0x4202u, M_I2S = 0x4203u;
        {
            MemoryStream ms = new MemoryStream();
            PHdr(ms, 1u, 0x08001001u, 96u); W32(ms, 2u);
            W32(ms, SG1); W32(ms, 3u); W32(ms, 0x0800100Eu); W32(ms, 4u); W32(ms, 2u); W32(ms, 0x0800100Fu); W32(ms, 4u); W32(ms, 2u); W32(ms, 0x08001010u); W32(ms, 4u); W32(ms, 1u);
            W32(ms, SG2); W32(ms, 3u); W32(ms, 0x0800100Eu); W32(ms, 4u); W32(ms, 2u); W32(ms, 0x0800100Fu); W32(ms, 4u); W32(ms, 2u); W32(ms, 0x08001010u); W32(ms, 4u); W32(ms, 1u);
            Pad8(ms);
            PHdr(ms, 1u, 0x08001000u, 128u); W32(ms, 2u);
            W32(ms, CT1); W32(ms, 4u); W32(ms, 0x08001011u); W32(ms, 8u); W32(ms, 1u); W32(ms, 0x0B001001u); W32(ms, 0x08001012u); W32(ms, 4u); W32(ms, 1u); W32(ms, 0x08001013u); W32(ms, 4u); W32(ms, 4096u); W32(ms, 0x08001014u); W32(ms, 4u); W32(ms, 2u);
            W32(ms, CT2); W32(ms, 4u); W32(ms, 0x08001011u); W32(ms, 8u); W32(ms, 1u); W32(ms, 0x0B001001u); W32(ms, 0x08001012u); W32(ms, 4u); W32(ms, 4u); W32(ms, 0x08001013u); W32(ms, 4u); W32(ms, 4096u); W32(ms, 0x08001014u); W32(ms, 4u); W32(ms, 2u);
            Pad8(ms);
            PHdr(ms, 1u, 0x08001002u, 56u); W32(ms, 2u);
            W32(ms, SG1); W32(ms, CT1); W32(ms, 2u); W32(ms, 0x07001000u); W32(ms, M_EP); W32(ms, 0x07001002u); W32(ms, M_GN);
            W32(ms, SG2); W32(ms, CT2); W32(ms, 1u); W32(ms, 0x0700100Eu); W32(ms, M_I2S);
            Pad8(ms);
            PHdr(ms, 1u, 0x08001003u, 80u); W32(ms, 3u);
            W32(ms, M_EP);  W32(ms, 1u); W32(ms, 0x08001015u); W32(ms, 8u); W32(ms, 0u); W32(ms, 1u);
            W32(ms, M_GN);  W32(ms, 1u); W32(ms, 0x08001015u); W32(ms, 8u); W32(ms, 1u); W32(ms, 1u);
            W32(ms, M_I2S); W32(ms, 1u); W32(ms, 0x08001015u); W32(ms, 8u); W32(ms, 1u); W32(ms, 0u);
            Pad8(ms);
            PHdr(ms, 1u, 0x08001004u, 40u); W32(ms, 2u);
            W32(ms, M_EP); W32(ms, 1u); W32(ms, M_GN);  W32(ms, 2u);
            W32(ms, M_GN); W32(ms, 1u); W32(ms, M_I2S); W32(ms, 2u);
            Pad8(ms);
            SendGpr(h, "GRAPH_OPEN", 1u, 0x01001000u, 0x103, ms.ToArray());
        }
        // MATCHED 32-bit 48kHz stereo on BOTH M_EP and M_I2S!
        { MemoryStream ms = new MemoryStream(); PHdr(ms, M_EP, 0x0800100Cu, 32u); W32(ms, 1u); W32(ms, 0x09001000u); W32(ms, 20u); W32(ms, 48000u); W16(ms, 32); W16(ms, 1); W16(ms, 32); W16(ms, 31); W16(ms, 1); W16(ms, 2); ms.WriteByte(1); ms.WriteByte(2); Pad8(ms); SendGpr(h, "EP_MF_32B", M_EP, 0x01001006u, 0x104, ms.ToArray()); }
        {
            uint[] cands = new uint[] { 0x0800101Au };
            foreach (uint pid in cands) {
                MemoryStream ms = new MemoryStream(); PHdr(ms, M_I2S, pid, 28u);
                W32(ms, 0u); W32(ms, 1u);            // lpaif_type 0 (LPAIF), intf_idx 1 (Secondary) - verified: drives GPIO 123 frame sync
                W16(ms, 1); W16(ms, 1);               // sync_src INTERNAL, ctrl_data_out_enable
                W32(ms, 0x3u);                        // slot_mask: slots 0,1
                W16(ms, 2); W16(ms, 32);              // nslots_per_frame 2, slot_width 32
                W16(ms, 1); W16(ms, 0); W16(ms, 1); W16(ms, 0);   // sync_mode LONG, no invert, 1-cycle delay, reserved
                Pad8(ms);
                uint st = SendGpr(h, "TDM_CFG_0x" + pid.ToString("X8"), 1u, 0x01001006u, 0x105, ms.ToArray());
                if (st == 0) { Console.WriteLine("TDM INTF CFG PARAM = 0x" + pid.ToString("X8")); break; }
            }
        }
        { MemoryStream ms = new MemoryStream(); PHdr(ms, M_I2S, 0x08001017u, 12u); W32(ms, 48000u); W16(ms, 32); W16(ms, 2); W32(ms, 1u); Pad8(ms); SendGpr(h, "HW_EP_32B", 1u, 0x01001006u, 0x106, ms.ToArray()); }
        { MemoryStream ms = new MemoryStream(); PHdr(ms, M_I2S, 0x08001018u, 4u); W32(ms, 1u); Pad8(ms); SendGpr(h, "HW_EP_FS", 1u, 0x01001006u, 0x107, ms.ToArray()); }
        { MemoryStream ms = new MemoryStream(); PHdr(ms, M_GN, 0x08001006u, 4u); W16(ms, 0x2000); W16(ms, 0); Pad8(ms); SendGpr(h, "GAIN_0DB", 1u, 0x01001006u, 0x108, ms.ToArray()); }
        { MemoryStream sl = new MemoryStream(); PHdr(sl, 1u, 0x08001005u, 12u); W32(sl, 2u); W32(sl, SG1); W32(sl, SG2); Pad8(sl); byte[] sgList = sl.ToArray(); SendGpr(h, "PREP", 1u, 0x01001001u, 0x109, sgList); SendGpr(h, "START", 1u, 0x01001002u, 0x10A, sgList);
          /* re-vote the bit clock with the I2S endpoint in place (sequence that made the amps lock: task-6956) */
          SendGpr(h, "STOP2", 1u, 0x01001003u, 0x10B, sgList);
          { MemoryStream ms = new MemoryStream(); PHdr(ms, 2u, 0x0800102Cu, 8u); W32(ms, 1u); W32(ms, 0x102u); SendGpr(h, "REL_102", 2u, 0x01001010u, 0x10C, ms.ToArray()); }
          { MemoryStream ms = new MemoryStream(); PHdr(ms, 2u, 0x0800102Cu, 8u); W32(ms, 1u); W32(ms, 0x202u); SendGpr(h, "REL_202", 2u, 0x01001010u, 0x10D, ms.ToArray()); }
          { MemoryStream ms = new MemoryStream(); PHdr(ms, 2u, 0x0800102Cu, 20u); W32(ms, 1u); W32(ms, 0x202u); W32(ms, 3072000u); W32(ms, 1u); W32(ms, 0u); SendGpr(h, "REQ_202", 2u, 0x0100100Fu, 0x10E, ms.ToArray()); }
          SendGpr(h, "PREP2", 1u, 0x01001001u, 0x110, sgList); SendGpr(h, "START2", 1u, 0x01001002u, 0x111, sgList);
          System.Threading.Thread.Sleep(150);
          Console.WriteLine(string.Format("AFTER START2 TFA 0x34: 10=0x{0:X4}", TfaCmd(h, 2, 0x34, 0x10, 0)));
        }

        // 5. Power on all 3 TFA9873 amps
        uint[] addrs = new uint[] { 0x34, 0x35, 0x36 };
        foreach (uint a in addrs) {
            TfaCmd(h, 3, a, 0x0F, 0x5A6B);
            uint fb = TfaCmd(h, 2, a, 0xFB, 0);
            TfaCmd(h, 3, a, 0xA0, fb ^ 0x5A);
            TfaCmd(h, 3, a, 0x02, 0x0628);
            TfaCmd(h, 3, a, 0x61, 0x0183);
            TfaCmd(h, 3, a, 0x63, 0x005A);
            TfaCmd(h, 3, a, 0x6F, 0x0082);
            TfaCmd(h, 3, a, 0x70, 0xA3EB);
            TfaCmd(h, 3, a, 0x71, 0x107E);
            TfaCmd(h, 3, a, 0x73, 0x0187);
            TfaCmd(h, 3, a, 0x83, 0x071C);
            TfaCmd(h, 3, a, 0x85, 0x0380);
            TfaCmd(h, 3, a, 0xD5, 0x004D);
            TfaCmd(h, 3, a, 0x01, 0x8004);
            TfaCmd(h, 3, a, 0x00, 0x4298);
        }

        // 6. Write 61440 bytes (7680 stereo 32-bit frames = 160 ms) of loud 440 Hz 32-bit PCM
        int pcmBytes = 61440;
        byte[] pcm = new byte[pcmBytes];
        for (int i = 0; i < pcmBytes / 8; i++) {
            int s = (int)(60000000.0 * Math.Sin(2.0 * Math.PI * 440.0 * i / 48000.0));   /* -31 dBFS: the -2 dBFS tone was startlingly loud */
            BitConverter.GetBytes(s).CopyTo(pcm, i*8 + 0);
            BitConverter.GetBytes(s).CopyTo(pcm, i*8 + 4);
        }
        for (int off = 0; off < pcmBytes; off += 4096) {
            int chunk = Math.Min(4096, pcmBytes - off);
            byte[] shm = new byte[4 + chunk];
            BitConverter.GetBytes((uint)off).CopyTo(shm, 0);
            Array.Copy(pcm, off, shm, 4, chunk);
            Ioctl(h, 0x0022A034u, shm, 4);
        }

        // 7. Map IOVA 0x00000001_10000000
        uint IOVA = 0x10000000u, MSW = 1u;
        byte[] map = new byte[44];
        BitConverter.GetBytes((uint)((6 << 4) | (44 << 8))).CopyTo(map, 0);
        BitConverter.GetBytes((uint)(2 | (3 << 8))).CopyTo(map, 4);
        BitConverter.GetBytes(0x2001u).CopyTo(map, 8); BitConverter.GetBytes(1u).CopyTo(map, 12);
        BitConverter.GetBytes(0x10Bu).CopyTo(map, 16); BitConverter.GetBytes(0x0100100Cu).CopyTo(map, 20);
        BitConverter.GetBytes((ushort)3).CopyTo(map, 24); BitConverter.GetBytes((ushort)1).CopyTo(map, 26);
        BitConverter.GetBytes(0u).CopyTo(map, 28);
        BitConverter.GetBytes(IOVA).CopyTo(map, 32); BitConverter.GetBytes(MSW).CopyTo(map, 36); BitConverter.GetBytes(bufSize).CopyTo(map, 40);
        Ioctl(h, 0x0022A028u, map, 4);
        uint mapHandle = 0;
        for (int t = 0; t < 20; t++) {
            System.Threading.Thread.Sleep(35);
            byte[] rx = Ioctl(h, 0x0022602Cu, null, 256);
            if (rx.Length >= 28 && BitConverter.ToUInt32(rx, 20) == 0x02001001u) { mapHandle = BitConverter.ToUInt32(rx, 24); break; }
        }
        Console.WriteLine("mapHandle=0x" + mapHandle.ToString("X8"));

        {
            uint r10 = TfaCmd(h, 2, 0x34, 0x10, 0);
            Console.WriteLine(string.Format("PRE-STREAM TFA 0x34: 10=0x{0:X4}", r10));
            if (r10 == 0x0016u || r10 == 0x0017u) {
                Console.WriteLine("NO I2S CLOCK AT THE AMP - not streaming (keeps adsp_apps intents intact)");
                if (!System.IO.File.Exists(@"C:\topaz\keep_graph")) { SendGpr(h, "STOP_END", 1u, 0x01001003u, 0x1F0, sgList0); SendGpr(h, "CLOSE_END", 1u, 0x01001004u, 0x1F1, sgList0); }
                else Console.WriteLine("graph left RUNNING for measurement");
                CloseHandle(h); return;
            }
        }
        // 8. Stream 20 buffers with at most 3 in flight (never overflow the 8-slot GLINK TX queue)
        int doneCnt = 0, sent = 0, inflight = 0, total = 12, idle = 0;
        while (doneCnt < total && idle < 40) {
            while (inflight < 3 && sent < total) {
                byte[] wr = new byte[24 + 44];
                BitConverter.GetBytes((uint)((6 << 4) | (68 << 8))).CopyTo(wr, 0);
                BitConverter.GetBytes((uint)(2 | (3 << 8))).CopyTo(wr, 4);
                BitConverter.GetBytes(0x2001u).CopyTo(wr, 8); BitConverter.GetBytes(M_EP).CopyTo(wr, 12);
                BitConverter.GetBytes(0xBB00u + (uint)sent).CopyTo(wr, 16); BitConverter.GetBytes(0x0400100Au).CopyTo(wr, 20);
                BitConverter.GetBytes(IOVA).CopyTo(wr, 24); BitConverter.GetBytes(MSW).CopyTo(wr, 28);
                BitConverter.GetBytes(mapHandle).CopyTo(wr, 32); BitConverter.GetBytes((uint)pcmBytes).CopyTo(wr, 36);
                Ioctl(h, 0x0022A028u, wr, 4);
                sent++; inflight++;
            }
            System.Threading.Thread.Sleep(20);
            byte[] rx = Ioctl(h, 0x0022602Cu, null, 256);
            if (rx.Length >= 40 && BitConverter.ToUInt32(rx, 20) == 0x05001004u) {
                doneCnt++; inflight--; idle = 0;
                if (doneCnt == 30) Console.WriteLine("MID-PLAYBACK PINS: " + Probe());
                if (doneCnt <= 3 || doneCnt == total) Console.WriteLine(string.Format("  DONE #{0} tok=0x{1:X} st=0x{2:X}", doneCnt, BitConverter.ToUInt32(rx,16), BitConverter.ToUInt32(rx,36)));
            } else if (rx.Length > 0) {
                Console.WriteLine(string.Format("  rx op=0x{0:X8} len={1}", rx.Length >= 24 ? BitConverter.ToUInt32(rx,20) : 0, rx.Length));
            } else idle++;
        }
        Console.WriteLine("SENT " + sent + " INFLIGHT " + inflight);
        Console.WriteLine("TOTAL DONE_V2: " + doneCnt + " / " + total);
        foreach (uint a in addrs) {
            Console.WriteLine(string.Format("POST TFA 0x{0:X2}: 10=0x{1:X4} 11=0x{2:X4} 13=0x{3:X4}",
                a, TfaCmd(h,2,a,0x10,0), TfaCmd(h,2,a,0x11,0), TfaCmd(h,2,a,0x13,0)));
        }
        CloseHandle(h);
    }
}
"@
Add-Type -TypeDefinition $code -Language CSharp
[AudioTdm]::Run()
'''
r = lab.run('phone', ['powershell', '-NoProfile', '-Command', ps], timeout=60)
print(r.get('output'))
