using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;

namespace Spor.Modules
{
    /// <summary>
    /// SRUM (System Resource Usage Monitor): bytes sent/received per program per hour, about 30-60 days back (data theft volume,
    /// programs that ran and are gone). Live state: TCP connections and listening ports with the owning program, DNS cache entries
    /// of remote access, tunnel, paste and file-sharing services.
    /// </summary>
    class Network : IModule
    {
        public string Id => "network";
        public string Name => "NETWORK";
        public string Description => "data sent per program (SRUM), connections now, DNS cache";

        Ctx c;

        public void Execute(Ctx ctx)
        {
            c = ctx;
            Srum();
            Connections();
            Dns();
        }

        bool Trusted(string p) => c.TrustedFile(p);   // location + valid signature, not a LOLBin

        // ---------------- SRUM ----------------
        void Srum()
        {
            var src = Path.Combine(c.WinDir, @"System32\sru\SRUDB.dat");
            c.Out.Sub($"Data sent and received per program in the last {c.Opt.Days} days (SRUM)",
                "Windows records this hourly. A large 'sent' for an unknown program can mean stolen data. Newest hour may be missing.");
            if (!File.Exists(src)) { c.Out.None("SRUDB.dat not found"); return; }
            var apps = new Dictionary<long, string>();
            var users = new Dictionary<long, string>();
            var agg = new Dictionary<long, (long Sent, long Recv, DateTime First, DateTime Last, HashSet<long> Users)>();
            void Add(long app, long user, DateTime t, long s, long r)
            {
                if (t < c.Since) return;
                if (!agg.TryGetValue(app, out var a)) a = (0, 0, t, t, new HashSet<long>());
                a.Users.Add(user);
                agg[app] = (a.Sent + s, a.Recv + r, t < a.First ? t : a.First, t > a.Last ? t : a.Last, a.Users);
            }
            try
            {
                using (var e = Ese.OpenCopy(c, src, "SRU", Path.Combine(c.Temp, "srum")))
                {
                    foreach (var r in e.Rows("SruDbIdMapTable", "IdType", "IdIndex", "IdBlob"))
                    {
                        var idx = Convert.ToInt64(r["IdIndex"] ?? 0L); var type = Convert.ToInt64(r["IdType"] ?? -1L);
                        if (!(r["IdBlob"] is byte[] b)) continue;
                        if (type == 3) { try { users[idx] = new SecurityIdentifier(b, 0).Value; } catch { } }
                        else apps[idx] = Encoding.Unicode.GetString(b).TrimEnd('\0');
                    }
                    foreach (var r in e.Rows("{973F5D5C-1D90-4944-BE8E-24B94231A174}", "AppId", "UserId", "TimeStamp", "BytesSent", "BytesRecvd"))
                        if (r["TimeStamp"] is DateTime t) Add(Convert.ToInt64(r["AppId"] ?? 0L), Convert.ToInt64(r["UserId"] ?? 0L), DateTime.SpecifyKind(t, DateTimeKind.Utc), Convert.ToInt64(r["BytesSent"] ?? 0L), Convert.ToInt64(r["BytesRecvd"] ?? 0L));
                    foreach (var r in e.Rows("{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}", "AppId", "UserId", "TimeStamp"))
                        if (r["TimeStamp"] is DateTime t) Add(Convert.ToInt64(r["AppId"] ?? 0L), Convert.ToInt64(r["UserId"] ?? 0L), DateTime.SpecifyKind(t, DateTimeKind.Utc), 0, 0);
                }
            }
            catch (Exception ex) { c.Out.None("could not read SRUM: " + ex.Message); return; }

            var rows = agg.Select(kv =>
            {
                var name = apps.TryGetValue(kv.Key, out var n) ? n : "(unknown SRUM app id " + kv.Key + ")";
                var path = c.DevicePath(name);
                var user = string.Join(", ", kv.Value.Users.Select(u => users.TryGetValue(u, out var s) ? c.UserOf(s) : "").Where(s => s.Length > 0 && !s.StartsWith("S-1-5-1")).Distinct());
                return (Path: path, IsFile: Rules.DrivePath.IsMatch(path), kv.Value.Sent, kv.Value.Recv, kv.Value.First, kv.Value.Last, User: user);
            }).ToList();
            // SRUM can hold the same program under several app ids (other path spelling, other user): one row per path, sums
            rows = rows.GroupBy(r => r.Path, Util.IC).Select(g => (Path: g.First().Path, IsFile: g.First().IsFile, Sent: g.Sum(r => r.Sent), Recv: g.Sum(r => r.Recv),
                        First: g.Min(r => r.First), Last: g.Max(r => r.Last),
                        User: string.Join(", ", g.SelectMany(r => r.User.Split(new[] { ", " }, StringSplitOptions.RemoveEmptyEntries)).Distinct()))).ToList();
            var shown = rows.Where(r => r.IsFile && (!Rules.Whitelist || !Trusted(r.Path) || Rules.Lol.IsMatch(r.Path))).OrderByDescending(r => r.Sent).ThenByDescending(r => r.Last).ToList();
            var st = new Table("first seen", "@last seen", "sent", "received", "[user", "!status", "<flags", "*program");
            int k = 0;
            foreach (var r in shown)
            {
                var fl = Rules.Flags(r.Path); var f = c.F(r.Path);
                st.Add(Log.T(r.First), Log.T(r.Last), Cmd.Bytes(r.Sent), Cmd.Bytes(r.Recv), r.User, f.Status, Rules.FlagCol(fl), f.Path);
                // timeline: the 60 programs that sent the most (the table lists all)
                if (k++ < 60 || Rules.Strong(fl).Count > 0) c.Event(r.First, "SRU", r.Path, $"SRUM first activity in the window; sent {Cmd.Bytes(r.Sent)} in total");
                if (r.Sent >= 50L << 20 && !c.SignedOk(r.Path)) c.Find(r.Last, $"{c.File(r.Path)} sent {Cmd.Bytes(r.Sent)} ({r.First:MM-dd} to {r.Last:MM-dd}, SRUM)", "last activity");
            }
            st.WriteTo(c.Out);
        }

        // ---------------- live connections ----------------
        [DllImport("iphlpapi.dll")] static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool order, int af, int cls, uint reserved);
        static string ProcPath(int pid)
        {
            if (pid == 0) return "System Idle";
            if (pid == 4) return "System";
            return Native.ProcessPath(pid) ?? "pid " + pid;
        }

        static readonly string[] States = { "?", "CLOSED", "LISTEN", "SYN_SENT", "SYN_RCVD", "ESTABLISHED", "FIN_WAIT1", "FIN_WAIT2", "CLOSE_WAIT", "CLOSING", "LAST_ACK", "TIME_WAIT", "DELETE_TCB" };

        static List<(int State, IPAddress L, int LPort, IPAddress R, int RPort, int Pid)> Tcp(int af)
        {
            var res = new List<(int, IPAddress, int, IPAddress, int, int)>();
            int size = 0;
            GetExtendedTcpTable(IntPtr.Zero, ref size, false, af, 5, 0);   // TCP_TABLE_OWNER_PID_ALL
            var buf = Marshal.AllocHGlobal(size + 4096); size += 4096;
            try
            {
                if (GetExtendedTcpTable(buf, ref size, false, af, 5, 0) != 0) return res;
                int n = Marshal.ReadInt32(buf);
                int rowSize = af == 2 ? 24 : 56;
                for (int i = 0; i < n; i++)
                {
                    var r = buf + 4 + i * rowSize;
                    int Port(int o) => (Marshal.ReadByte(r, o) << 8) | Marshal.ReadByte(r, o + 1);
                    if (af == 2)
                        res.Add((Marshal.ReadInt32(r, 0), new IPAddress((uint)Marshal.ReadInt32(r, 4)), Port(8), new IPAddress((uint)Marshal.ReadInt32(r, 12)), Port(16), Marshal.ReadInt32(r, 20)));
                    else
                    {
                        var la = new byte[16]; var ra = new byte[16];
                        Marshal.Copy(r, la, 0, 16); Marshal.Copy(r + 24, ra, 0, 16);
                        res.Add((Marshal.ReadInt32(r, 48), new IPAddress(la), Port(20), new IPAddress(ra), Port(44), Marshal.ReadInt32(r, 52)));
                    }
                }
            }
            finally { Marshal.FreeHGlobal(buf); }
            return res;
        }

        static bool Public(IPAddress a)
        {
            if (IPAddress.IsLoopback(a) || a.Equals(IPAddress.Any) || a.Equals(IPAddress.IPv6Any)) return false;
            if (a.IsIPv4MappedToIPv6) a = a.MapToIPv4();
            var b = a.GetAddressBytes();
            if (b.Length == 4) return !(b[0] == 10 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31) || (b[0] == 192 && b[1] == 168) || (b[0] == 169 && b[1] == 254) || b[0] == 127 || b[0] == 0 || b[0] >= 224 || (b[0] == 100 && b[1] >= 64 && b[1] <= 127));
            return !(a.IsIPv6LinkLocal || a.IsIPv6SiteLocal || a.IsIPv6Multicast || (b[0] & 0xFE) == 0xFC);
        }

        void Connections()
        {
            c.Out.Sub(Rules.Whitelist ? "Network connections now: programs outside trusted locations, LOLBins, unsigned programs" : "Network connections now",
                "Connections to public addresses and ports listening for the network, per program.");
            var all = Tcp(2).Concat(Tcp(23)).ToList();
            var paths = new Dictionary<int, string>();
            string P(int pid) => paths.TryGetValue(pid, out var p) ? p : paths[pid] = ProcPath(pid);
            var ct = new Table("[pid", "!status", "<flags", "*program", "connected to", "listening on");
            foreach (var g in all.GroupBy(x => x.Pid).OrderBy(g => P(g.Key), StringComparer.OrdinalIgnoreCase))
            {
                var path = P(g.Key);
                var est = g.Where(x => x.State == 5 && Public(x.R)).Select(x => $"{x.R}:{x.RPort}").Distinct().ToList();
                var lis = g.Where(x => x.State == 2 && !IPAddress.IsLoopback(x.L)).Select(x => x.LPort).Distinct().OrderBy(x => x).ToList();
                if (est.Count == 0 && lis.Count == 0) continue;
                if (g.Key == System.Diagnostics.Process.GetCurrentProcess().Id) continue;   // Spor itself (certificate revocation lists)
                var fl = Rules.Flags(path);
                var f = Rules.DrivePath.IsMatch(path) ? c.F(path) : (path, "-");
                var disp = f.Item1;
                bool unsigned = Ctx.BadSig(f.Item2);
                if (Rules.Whitelist && Rules.DrivePath.IsMatch(path) && Trusted(path) && !fl.Contains("!lolbin") && !unsigned) continue;
                if (Rules.Whitelist && !Rules.DrivePath.IsMatch(path)) continue;   // System, protected processes
                ct.Add(g.Key.ToString(), f.Item2, Rules.FlagCol(fl), disp, string.Join(", ", est), string.Join(", ", lis.Select(x => "port " + x)));
                if (est.Count > 0 && (fl.Contains("!lolbin") || (unsigned && !Trusted(path))))
                    c.Find($"{disp} is connected to {string.Join(", ", est.Take(3))}{Rules.FlagText(fl)}");
            }
            ct.WriteTo(c.Out);
        }

        // ---------------- DNS cache ----------------
        [StructLayout(LayoutKind.Sequential)]
        struct DNS_CACHE_ENTRY { public IntPtr Next; public IntPtr Name; public ushort Type; public ushort DataLength; public uint Flags; }
        [DllImport("dnsapi.dll")] static extern bool DnsGetCacheDataTable(out IntPtr table);

        static readonly (string Cat, Func<string, bool> Match)[] Domains =
        {
            ("remote access", new Regex(@"(^|\.)(anydesk\.com|teamviewer\.com|screenconnect\.com|connectwise\.com|splashtop\.com|rustdesk\.com|atera(agent)?\.com|ninjarmm\.com|action1\.com|getscreen\.me|supremocontrol\.com|remoteutilities\.com|ammyy\.com|aeroadmin\.com|radmin\.com|zohoassist\.com|logmein\.com|gotoassist\.com|goto\.com|simple-help\.com|meshcentral\.com|tacticalrmm\.com|level\.io|syncromsp\.com|pulseway\.com|dwservice\.net|ultraviewer\.net|hoptodesk\.com|remotepc\.com|netsupportsoftware\.com|parsec\.app)$", Util.RX).IsMatch),
            ("tunnel / dynamic DNS", new Regex(@"(^|\.)(ngrok(-free)?\.(io|app|dev)|trycloudflare\.com|serveo\.net|localtonet\.com|localhost\.run|loca\.lt|pinggy\.io|playit\.gg|portmap\.io|duckdns\.org|no-ip\.(com|org|biz)|ddns\.net|hopto\.org|zapto\.org|sytes\.net|servebeer\.com|dynu\.com|freedns\.afraid\.org|ydns\.eu)$", Util.RX).IsMatch),
            ("paste / file sharing", new Regex(@"(^|\.)(pastebin\.com|paste\.ee|rentry\.co|hastebin\.com|ghostbin\.\w+|transfer\.sh|file\.io|gofile\.io|anonfiles\.com|catbox\.moe|litterbox\.catbox\.moe|temp\.sh|bashupload\.com|mega\.nz|mediafire\.com|pixeldrain\.com|sendspace\.com|uploadnow\.io)$", Util.RX).IsMatch),
            ("bot / webhook API", new Regex(@"(^|\.)(api\.telegram\.org|discord(app)?\.com|hooks\.slack\.com|webhook\.site|pipedream\.net|requestbin\.\w+)$", Util.RX).IsMatch),
            ("IP lookup", new Regex(@"(^|\.)(ipinfo\.io|ip-api\.com|ifconfig\.me|api\.ipify\.org|checkip\.amazonaws\.com|icanhazip\.com|myexternalip\.com|ipwho\.is|wtfismyip\.com|geoplugin\.net)$", Util.RX).IsMatch),
            ("victim ID in name", HostNames.VictimId),
            ("abused TLD", HostNames.AbusedTld),
        };

        void Dns()
        {
            c.Out.Sub(Rules.Whitelist ? "DNS cache: remote access, tunnel, paste/file sharing, bot API and IP lookup services, victim IDs, abused TLDs" : "DNS cache",
                "Names this PC looked up recently (since the last restart, a few hours at most per entry). Normal use explains many.");
            var names = new List<string>();
            try
            {
                using (var q = new System.Management.ManagementObjectSearcher(@"\\.\root\StandardCimv2", "SELECT Entry, Name FROM MSFT_DNSClientCache"))
                    foreach (System.Management.ManagementObject o in q.Get()) { names.Add(Convert.ToString(o["Entry"])); names.Add(Convert.ToString(o["Name"])); }
            }
            catch (Exception ex) { c.Err.Add("DNS cache (WMI): " + ex.Message); }
            try
            {
                if (names.Count == 0 && DnsGetCacheDataTable(out var p))
                    for (var e = p; e != IntPtr.Zero;)
                    {
                        var d = (DNS_CACHE_ENTRY)Marshal.PtrToStructure(e, typeof(DNS_CACHE_ENTRY));
                        if (d.Name != IntPtr.Zero) names.Add(Marshal.PtrToStringUni(d.Name));
                        e = d.Next;
                    }
            }
            catch (Exception ex) { c.Out.None("cannot read the DNS cache: " + ex.Message); return; }
            names = names.Where(n => !string.IsNullOrEmpty(n)).Select(n => n.TrimEnd('.').ToLowerInvariant()).Distinct().OrderBy(n => n).ToList();
            foreach (var n in names) c.Observe("domain", n, null, "DNS cache " + n);
            var dt = new Table("[category", "*name");
            foreach (var (cat, match) in Domains)
            {
                var hit = names.Where(match).ToList();
                foreach (var h in hit) dt.Add(cat, h);
                if (hit.Count > 0 && (cat == "remote access" || cat == "tunnel / dynamic DNS" || cat == "victim ID in name")) c.Find($"DNS cache, {cat}: {string.Join(", ", hit)}");
            }
            if (!Rules.Whitelist)
                foreach (var n in names.Where(n => !Domains.Any(d => d.Match(n)))) dt.Add("-", n);
            c.Out.Comment($"{names.Count} names cached");
            dt.WriteTo(c.Out, "none of these");
        }
    }
}
