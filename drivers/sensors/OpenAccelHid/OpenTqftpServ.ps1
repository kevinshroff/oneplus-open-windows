# SPDX-License-Identifier: MIT
# OpenTqftpServ.ps1: Userspace Qualcomm TFTP-over-QRTR daemon (service 4096) for Windows 11 ARM64.
# Bridges ADSP sensors_pd / audio_pd remote filesystem requests over OpenChargerKeeper's GLINK IPCRTR
# IOCTLs (IOCTL_CK_QRTR_SEND / IOCTL_CK_QRTR_RECV) to C:\OpenG81\persist\.

param(
    [string]$PersistRoot = "C:\OpenG81\persist",
    [string]$LogPath     = "C:\OpenG81\OpenTqftpServ.log",
    [int]$MaxSeconds     = 0
)

$cs = @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Microsoft.Win32.SafeHandles;

public static class OpenTqftp {
    const uint GENERIC_READ = 0x80000000;
    const uint GENERIC_WRITE = 0x40000000;
    const uint OPEN_EXISTING = 3;
    const uint IOCTL_CK_ACCEL     = 0x0022600Cu;
    const uint IOCTL_CK_QRTR_SEND = 0x0022A010u;
    const uint IOCTL_CK_QRTR_RECV = 0x00226014u;

    const uint QRTR_PORT_CTRL   = 0xFFFFFFFEu;
    const uint QRTR_LOCAL_NODE  = 1u;
    const uint TFTP_SVC_ID      = 4096u;
    const uint TFTP_LISTEN_PORT = 0x2000u;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern SafeFileHandle CreateFile(string name, uint access, uint share, IntPtr sec, uint disp, uint flags, IntPtr tmpl);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool DeviceIoControl(SafeFileHandle h, uint code, byte[] inBuf, int inLen, byte[] outBuf, int outLen, out int ret, IntPtr ov);

    class Session {
        public uint LocalPort;
        public uint PeerNode;
        public uint PeerPort;
        public bool IsWrite;
        public string FilePath;
        public byte[] Data;
        public int BlkSize = 512;
        public int NextBlock = 1;
        public bool Done = false;
        public MemoryStream WriteBuf;
    }

    static StreamWriter _log;
    static void Log(string msg) {
        string line = DateTime.UtcNow.ToString("HH:mm:ss.fff") + " " + msg;
        Console.WriteLine(line);
        if (_log != null) { _log.WriteLine(line); _log.Flush(); }
    }

    static uint R32(byte[] b, int o) { return BitConverter.ToUInt32(b, o); }
    static void W32(byte[] b, int o, uint v) {
        b[o] = (byte)v; b[o+1] = (byte)(v >> 8); b[o+2] = (byte)(v >> 16); b[o+3] = (byte)(v >> 24);
    }

    static bool SendQrtr(SafeFileHandle h, uint type, uint srcPort, uint dstNode, uint dstPort, byte[] payload) {
        int plen = payload != null ? payload.Length : 0;
        int aligned = (plen + 3) & ~3;
        byte[] pkt = new byte[32 + aligned];
        W32(pkt, 0, 1u);
        W32(pkt, 4, type);
        W32(pkt, 8, QRTR_LOCAL_NODE);
        W32(pkt, 12, srcPort);
        W32(pkt, 16, 0u);
        W32(pkt, 20, (uint)plen);
        W32(pkt, 24, dstNode);
        W32(pkt, 28, dstPort);
        if (plen > 0) Buffer.BlockCopy(payload, 0, pkt, 32, plen);
        int ret;
        for (int tries = 0; tries < 20; tries++) {
            if (DeviceIoControl(h, IOCTL_CK_QRTR_SEND, pkt, pkt.Length, null, 0, out ret, IntPtr.Zero))
                return true;
            Thread.Sleep(5);
        }
        Log("WARN: SendQrtr failed type=" + type + " len=" + pkt.Length);
        return false;
    }

    static void PublishService(SafeFileHandle h, uint svc, uint inst, uint port) {
        byte[] ctrl = new byte[20];
        W32(ctrl, 0, 4u); // QRTR_TYPE_NEW_SERVER
        W32(ctrl, 4, svc);
        W32(ctrl, 8, inst);
        W32(ctrl, 12, QRTR_LOCAL_NODE);
        W32(ctrl, 16, port);
        SendQrtr(h, 4u, QRTR_PORT_CTRL, 5u, QRTR_PORT_CTRL, ctrl);
        SendQrtr(h, 4u, QRTR_PORT_CTRL, 0xFFFFFFFFu, QRTR_PORT_CTRL, ctrl);
        Log(string.Format("Published QRTR NEW_SERVER svc={0} inst={1} node={2} port=0x{3:x} -> ADSP(5)+BCAST", svc, inst, QRTR_LOCAL_NODE, port));
    }

    static string ResolvePath(string root, string req) {
        string clean = req.Replace('\\', '/').TrimStart('/');
        string[] prefixes = new[] {
            "readonly/vendor/firmware/", "readonly/firmware/", "readonly/",
            "readwrite/", "mnt/vendor/persist/", "persist/"
        };
        var candidates = new List<string>();
        candidates.Add(clean);
        foreach (var p in prefixes) {
            if (clean.StartsWith(p, StringComparison.OrdinalIgnoreCase))
                candidates.Add(clean.Substring(p.Length));
        }
        foreach (var c in candidates) {
            string p1 = Path.Combine(root, c.Replace('/', Path.DirectorySeparatorChar));
            if (File.Exists(p1)) return p1;
            string p2 = Path.Combine(root, "rfs", c.Replace('/', Path.DirectorySeparatorChar));
            if (File.Exists(p2)) return p2;
            string p3 = Path.Combine(root, "hlos_rfs", c.Replace('/', Path.DirectorySeparatorChar));
            if (File.Exists(p3)) return p3;
            string p4 = Path.Combine(root, "sensors", c.Replace('/', Path.DirectorySeparatorChar));
            if (File.Exists(p4)) return p4;
        }
        return null;
    }

    static void SendError(SafeFileHandle h, uint localPort, uint dstNode, uint dstPort, ushort code, string msg) {
        byte[] mb = Encoding.ASCII.GetBytes(msg);
        byte[] p = new byte[4 + mb.Length + 1];
        p[0] = 0; p[1] = 5; // ERROR
        p[2] = (byte)(code >> 8); p[3] = (byte)(code & 0xFF);
        Buffer.BlockCopy(mb, 0, p, 4, mb.Length);
        SendQrtr(h, 1u, localPort, dstNode, dstPort, p);
    }

    static void SendDataBlock(SafeFileHandle h, Session s, int blk) {
        int off = (blk - 1) * s.BlkSize;
        int len = Math.Max(0, Math.Min(s.BlkSize, s.Data.Length - off));
        byte[] p = new byte[4 + len];
        p[0] = 0; p[1] = 3; // DATA
        p[2] = (byte)((blk >> 8) & 0xFF);
        p[3] = (byte)(blk & 0xFF);
        if (len > 0) Buffer.BlockCopy(s.Data, off, p, 4, len);
        SendQrtr(h, 1u, s.LocalPort, s.PeerNode, s.PeerPort, p);
        if (len < s.BlkSize) s.Done = true;
    }

    static void SendAck(SafeFileHandle h, uint localPort, uint dstNode, uint dstPort, int blk) {
        byte[] p = new byte[4];
        p[0] = 0; p[1] = 4; // ACK
        p[2] = (byte)((blk >> 8) & 0xFF);
        p[3] = (byte)(blk & 0xFF);
        SendQrtr(h, 1u, localPort, dstNode, dstPort, p);
    }

    public static int Run(string persistRoot, string logPath, int maxSeconds) {
        if (!string.IsNullOrEmpty(logPath)) {
            _log = new StreamWriter(logPath, false, Encoding.UTF8);
        }
        SafeFileHandle h = CreateFile(@"\\.\OpenChargerKeeper", GENERIC_READ | GENERIC_WRITE, 3, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
        if (h.IsInvalid) {
            Log("FATAL: cannot open \\\\.\\OpenChargerKeeper err=" + Marshal.GetLastWin32Error());
            return 1;
        }
        Log("Opened \\\\.\\OpenChargerKeeper; persistRoot=" + persistRoot);

        // Publish Qualcomm TFTP service 4096 for all standard instances (0=MPSS, 1=ADSP, 2=SLPI, 3=CDSP)
        PublishService(h, TFTP_SVC_ID, 1u, TFTP_LISTEN_PORT);
        PublishService(h, TFTP_SVC_ID, 2u, TFTP_LISTEN_PORT);
        PublishService(h, TFTP_SVC_ID, 0u, TFTP_LISTEN_PORT);
        PublishService(h, TFTP_SVC_ID, 3u, TFTP_LISTEN_PORT);

        var sessions = new Dictionary<uint, Session>();
        uint nextPort = 0x2100u;
        byte[] rxBuf = new byte[1536];
        byte[] accBuf = new byte[1024];
        DateTime start = DateTime.UtcNow;
        DateTime lastStat = DateTime.MinValue;
        uint lastSvcs = 0, lastAccelSeq = 0;

        while (true) {
            if (maxSeconds > 0 && (DateTime.UtcNow - start).TotalSeconds >= maxSeconds) break;

            int got = 0;
            bool ok = DeviceIoControl(h, IOCTL_CK_QRTR_RECV, null, 0, rxBuf, rxBuf.Length, out got, IntPtr.Zero);
            if (ok && got >= 32) {
                uint ver = R32(rxBuf, 0);
                uint type = R32(rxBuf, 4);
                uint srcNode = R32(rxBuf, 8);
                uint srcPort = R32(rxBuf, 12);
                uint psize = R32(rxBuf, 20);
                uint dstNode = R32(rxBuf, 24);
                uint dstPort = R32(rxBuf, 28);

                if (type == 4u && psize >= 20) {
                    uint svc = R32(rxBuf, 36), inst = R32(rxBuf, 40), n = R32(rxBuf, 44), p = R32(rxBuf, 48);
                    Log(string.Format("RX NEW_SERVER svc={0} inst={1} node={2} port=0x{3:x}", svc, inst, n, p));
                } else if (type == 6u && psize >= 20) {
                    uint svc = R32(rxBuf, 36), inst = R32(rxBuf, 40);
                    Log(string.Format("RX NEW_LOOKUP svc={0} inst={1} from {2}:0x{3:x}", svc, inst, srcNode, srcPort));
                    if (svc == TFTP_SVC_ID) {
                        PublishService(h, svc, inst, TFTP_LISTEN_PORT);
                    }
                } else if (type == 1u && psize >= 2 && (dstPort == TFTP_LISTEN_PORT || sessions.ContainsKey(dstPort))) {
                    ushort op = (ushort)((rxBuf[32] << 8) | rxBuf[33]);
                    if (dstPort == TFTP_LISTEN_PORT && (op == 1 || op == 2)) {
                        // Parse null-terminated strings: filename, mode, [opt, val]...
                        var parts = new List<string>();
                        int idx = 34, end = 32 + (int)psize;
                        while (idx < end) {
                            int nul = Array.IndexOf<byte>(rxBuf, 0, idx, end - idx);
                            if (nul < 0) nul = end;
                            parts.Add(Encoding.ASCII.GetString(rxBuf, idx, nul - idx));
                            idx = nul + 1;
                        }
                        string fname = parts.Count > 0 ? parts[0] : "";
                        var opts = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                        for (int i = 2; i + 1 < parts.Count; i += 2) opts[parts[i]] = parts[i + 1];

                        uint sport = nextPort++;
                        if (nextPort > 0x2FFF) nextPort = 0x2100u;

                        Log(string.Format("TFTP {0} '{1}' from {2}:0x{3:x} -> port 0x{4:x} opts={5}",
                            op == 1 ? "RRQ" : "WRQ", fname, srcNode, srcPort, sport, opts.Count));

                        if (op == 1) {
                            string resolved = ResolvePath(persistRoot, fname);
                            if (resolved == null) {
                                Log("  -> ENOENT: " + fname);
                                SendError(h, sport, srcNode, srcPort, 1, "File not found");
                            } else {
                                byte[] fdata = File.ReadAllBytes(resolved);
                                var s = new Session {
                                    LocalPort = sport, PeerNode = srcNode, PeerPort = srcPort,
                                    IsWrite = false, FilePath = resolved, Data = fdata, BlkSize = 512, NextBlock = 1
                                };
                                var oack = new MemoryStream();
                                oack.WriteByte(0); oack.WriteByte(6);
                                bool hasOack = false;
                                if (opts.ContainsKey("blksize")) {
                                    int reqBlk;
                                    if (int.TryParse(opts["blksize"], out reqBlk)) {
                                        s.BlkSize = Math.Max(64, Math.Min(1024, reqBlk));
                                    }
                                    byte[] k = Encoding.ASCII.GetBytes("blksize\0" + s.BlkSize + "\0");
                                    oack.Write(k, 0, k.Length);
                                    hasOack = true;
                                }
                                if (opts.ContainsKey("tsize")) {
                                    byte[] k = Encoding.ASCII.GetBytes("tsize\0" + fdata.Length + "\0");
                                    oack.Write(k, 0, k.Length);
                                    hasOack = true;
                                }
                                if (opts.ContainsKey("rsize")) {
                                    byte[] k = Encoding.ASCII.GetBytes("rsize\0" + fdata.Length + "\0");
                                    oack.Write(k, 0, k.Length);
                                    hasOack = true;
                                }
                                sessions[sport] = s;
                                Log("  -> SERVING " + resolved + " (" + fdata.Length + " B, blksize=" + s.BlkSize + ")");
                                if (hasOack) {
                                    SendQrtr(h, 1u, sport, srcNode, srcPort, oack.ToArray());
                                } else {
                                    SendDataBlock(h, s, 1);
                                }
                            }
                        } else {
                            // WRQ
                            string safeRel = fname.Replace('\\', '/').TrimStart('/').Replace("..", "_");
                            string outPath = Path.Combine(persistRoot, "rw", safeRel.Replace('/', Path.DirectorySeparatorChar));
                            Directory.CreateDirectory(Path.GetDirectoryName(outPath));
                            var s = new Session {
                                LocalPort = sport, PeerNode = srcNode, PeerPort = srcPort,
                                IsWrite = true, FilePath = outPath, WriteBuf = new MemoryStream(), BlkSize = 512
                            };
                            sessions[sport] = s;
                            SendAck(h, sport, srcNode, srcPort, 0);
                        }
                    } else if (sessions.ContainsKey(dstPort)) {
                        var s = sessions[dstPort];
                        if (op == 4 && !s.IsWrite && psize >= 4) {
                            int ackBlk = (rxBuf[34] << 8) | rxBuf[35];
                            if (s.Done) {
                                sessions.Remove(dstPort);
                            } else {
                                SendDataBlock(h, s, ackBlk + 1);
                            }
                        } else if (op == 3 && s.IsWrite && psize >= 4) {
                            int blk = (rxBuf[34] << 8) | rxBuf[35];
                            int dlen = (int)psize - 4;
                            if (dlen > 0) s.WriteBuf.Write(rxBuf, 36, dlen);
                            SendAck(h, s.LocalPort, s.PeerNode, s.PeerPort, blk);
                            if (dlen < s.BlkSize) {
                                File.WriteAllBytes(s.FilePath, s.WriteBuf.ToArray());
                                Log("  -> WROTE " + s.FilePath + " (" + s.WriteBuf.Length + " B)");
                                sessions.Remove(dstPort);
                            }
                        } else if (op == 5) {
                            sessions.Remove(dstPort);
                        }
                    }
                } else {
                    Log(string.Format("RX QRTR type={0} {1}:0x{2:x} -> {3}:0x{4:x} len={5}", type, srcNode, srcPort, dstNode, dstPort, psize));
                }
            } else {
                Thread.Sleep(2);
            }

            if ((DateTime.UtcNow - lastStat).TotalSeconds >= 2) {
                lastStat = DateTime.UtcNow;
                int ag = 0;
                if (DeviceIoControl(h, IOCTL_CK_ACCEL, null, 0, accBuf, accBuf.Length, out ag, IntPtr.Zero) && ag >= 88) {
                    uint snsFound = R32(accBuf, 24);
                    uint suidFound = R32(accBuf, 40);
                    uint accelValid = R32(accBuf, 48);
                    uint accelSeq = R32(accBuf, 52);
                    int ax = BitConverter.ToInt32(accBuf, 56);
                    int ay = BitConverter.ToInt32(accBuf, 60);
                    int az = BitConverter.ToInt32(accBuf, 64);
                    uint svcs = R32(accBuf, 84);
                    if (svcs != lastSvcs || accelSeq != lastAccelSeq) {
                        lastSvcs = svcs; lastAccelSeq = accelSeq;
                        Log(string.Format("ACCEL svcs={0} sns={1} suid={2} valid={3} seq={4} xyz=({5},{6},{7}) mG",
                            svcs, snsFound, suidFound, accelValid, accelSeq, ax, ay, az));
                    }
                }
            }
        }
        h.Dispose();
        if (_log != null) _log.Dispose();
        return 0;
    }
}
'@

Add-Type -TypeDefinition $cs -Language CSharp
[OpenTqftp]::Run($PersistRoot, $LogPath, $MaxSeconds)
