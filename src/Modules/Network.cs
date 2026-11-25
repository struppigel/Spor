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
            Proxy();
            Dns();
        }

        // ---------------- Proxy ----------------

        public const string LocalProxyFlag = "!local-proxy";

        /// <summary>
        /// (pure) Host and port of a WinINet / WinHTTP proxy value: "127.0.0.1:57352", "http=127.0.0.1:8080;https=..." (the first
        /// entry), "socks=host:1080"; null when there is none.
        /// </summary>
        internal static (string Host, int Port)? ProxyTarget(string value)
        {
            var first = (value ?? "").Split(';').Select(x => x.Trim()).FirstOrDefault(x => x.Length > 0);
            if (first == null) return null;
            int eq = first.IndexOf('=');
            if (eq >= 0) first = first.Substring(eq + 1);
            first = Regex.Replace(first, @"^[a-z]+://", "", RegexOptions.IgnoreCase).TrimEnd('/');
            var m = Regex.Match(first, @"^\[?([^\]\s]+?)\]?(?::(\d{1,5}))?$");
            if (!m.Success) return null;
            return (m.Groups[1].Value, m.Groups[2].Success ? int.Parse(m.Groups[2].Value) : 80);
        }

        /// <summary>(pure) Every entry of a per-protocol proxy value ("ftp=x:21;http=127.0.0.1:8080;https=..."), as ProxyTarget reads one.</summary>
        internal static List<(string Host, int Port)> ProxyTargets(string value) =>
            (value ?? "").Split(';').Select(x => ProxyTarget(x)).Where(x => x.HasValue).Select(x => x.Value).Distinct().ToList();

        /// <summary>(pure) A proxy on this PC or the local network: localhost, loopback, private and link-local addresses.</summary>
        internal static bool LocalOrLan(string host)
        {
            if (string.IsNullOrEmpty(host)) return false;
            if (host.Equals("localhost", StringComparison.OrdinalIgnoreCase)) return true;
            return IPAddress.TryParse(host, out var a) && !Public(a);
        }

        /// <summary>
        /// (pure) The proxy of WinHTTP's WinHttpSettings value (netsh winhttp set proxy): DWORD version, DWORD counter, DWORD flags
        /// (3 = a proxy), DWORD length, the proxy as ASCII, then the bypass list; null when it is direct access.
        /// </summary>
        internal static string WinHttpProxy(byte[] b)
        {
            if (b == null || b.Length < 16) return null;
            int flags = BitConverter.ToInt32(b, 8), len = BitConverter.ToInt32(b, 12);
            if ((flags & 2) == 0 || len <= 0 || len > b.Length - 16) return null;   // no int overflow on a crafted length
            return System.Text.Encoding.ASCII.GetString(b, 16, len);
        }

        /// <summary>
        /// Proxy settings: per user (WinINet, what browsers use) and the machine's (policy and WinHTTP). A proxy on this PC or the LAN
        /// gets !local-proxy and the program listening on its port (a man-in-the-middle proxy reads all traffic, HTTPS too with a root
        /// certificate it installed: WEEVILPROXY); a proxy script (PAC) too; any other proxy the context flag !proxy.
        /// </summary>
        void Proxy()
        {
            c.Out.Sub("Proxy settings", "where WinINet (browsers) and WinHTTP send web traffic; listening = the program that has the proxy's port open now");
            var t = new Table("@changed", "[scope", "<flags", "*proxy", "=details");
            var listeners = new Dictionary<int, string>();
            try
            {
                foreach (var x in Tcp(2).Concat(Tcp(23)).Where(x => x.State == 2))
                    if (!listeners.ContainsKey(x.LPort)) listeners[x.LPort] = $"{ProcPath(x.Pid)} (pid {x.Pid})";
            }
            catch { }
            void Row(DateTime? when, string scope, bool enabled, string server, string pac)
            {
                foreach (var (value, isPac) in new[] { (server, false), (pac, true) })
                {
                    if (string.IsNullOrWhiteSpace(value)) continue;
                    var fl = new List<string>();
                    var details = new List<string>();
                    if (isPac) { details.Add("proxy script (PAC)"); fl.Add(LocalProxyFlag); }
                    else if (!enabled) details.Add("not enabled");
                    else if (ProxyTargets(value).Where(x => LocalOrLan(x.Host)).ToList() is var local && local.Count > 0)
                    {
                        // any local entry (http, https or socks): the program listening on each port
                        fl.Add(LocalProxyFlag);
                        foreach (var port in local.Select(x => x.Port).Distinct())
                            details.Add(listeners.TryGetValue(port, out var who) ? "listening: " + who : $"nothing listening on port {port} now");
                    }
                    else fl.Add("!proxy");
                    t.Add(Log.T(when), scope, Rules.FlagCol(fl), Rules.Fix(value), string.Join("; ", details));
                    c.Observe("domain", ProxyTarget(value)?.Host, when);
                    if (fl.Count > 0) c.Find(when, $"proxy ({scope}): {Rules.Fix(value)}", details.Count > 0 ? string.Join("; ", details) : null, fl);
                }
            }
            const string Inet = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
            foreach (var h in c.Hives)
                try
                {
                    using (var k = h.Root.OpenSubKey(Inet))
                        if (k != null) Row(Native.LastWrite(k), "user " + h.User, Convert.ToInt32(k.GetValue("ProxyEnable") ?? 0) == 1,
                                           Convert.ToString(k.GetValue("ProxyServer")), Convert.ToString(k.GetValue("AutoConfigURL")));
                }
                catch (Exception e) { c.Err.Add("proxy " + h.User + ": " + e.Message); }
            try
            {
                using (var k = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(Inet))
                    if (k != null) Row(Native.LastWrite(k), "machine", Convert.ToInt32(k.GetValue("ProxyEnable") ?? 0) == 1,
                                       Convert.ToString(k.GetValue("ProxyServer")), Convert.ToString(k.GetValue("AutoConfigURL")));
                using (var k = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(Inet + @"\Connections"))
                    if (k?.GetValue("WinHttpSettings") is byte[] wh && WinHttpProxy(wh) is string winhttp) Row(Native.LastWrite(k), "WinHTTP", true, winhttp, null);
            }
            catch (Exception e) { c.Err.Add("proxy (machine): " + e.Message); }
            t.WriteTo(c.Out, "no proxy set");
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
                var user = string.Join(", ", kv.Value.Users.Select(u => users.TryGetValue(u, out var s) ? c.UserOf(s) : "").Where(s => s.Length > 0 && !s.StartsWith("S-1-5-1") && s != "S-1-5-20").Distinct());   // no tag for SYSTEM, LOCAL and NETWORK SERVICE (like other service rows)
                return (Path: path, IsFile: Rules.DrivePath.IsMatch(path), kv.Value.Sent, kv.Value.Recv, kv.Value.First, kv.Value.Last, User: user);
            }).ToList();
            // SRUM can hold the same program under several app ids (other path spelling, other user): one row per path, sums
            rows = rows.GroupBy(r => r.Path, Util.IC).Select(g => (Path: g.First().Path, IsFile: g.First().IsFile, Sent: g.Sum(r => r.Sent), Recv: g.Sum(r => r.Recv),
                        First: g.Min(r => r.First), Last: g.Max(r => r.Last),
                        User: string.Join(", ", g.SelectMany(r => r.User.Split(new[] { ", " }, StringSplitOptions.RemoveEmptyEntries)).Distinct()))).ToList();
            var shown = rows.Where(r => r.IsFile && (!Rules.Whitelist || !Trusted(r.Path) || Rules.Lol.IsMatch(r.Path))).OrderByDescending(r => r.Sent).ThenByDescending(r => r.Last).ToList();
            var st = new Table("first seen", "@last seen", "sent", "received", "[user", "!status", "<flags", "*program");
            int k = 0, staging = 0;
            foreach (var r in shown)
            {
                var fl = c.WithLolbinCopy(r.Path, Rules.Flags(r.Path));   // the flags the timeline gives the file (!lolbin-copy too)
                // whitelist: updaters' staged packages (gone after the update; timeline too)
                if (Rules.Whitelist && Rules.InUpdaterStaging(r.Path) && Rules.Strong(fl).Count == 0) { staging++; continue; }
                var f = c.F(r.Path);
                st.Add(Log.T(r.First), Log.T(r.Last), Cmd.Bytes(r.Sent), Cmd.Bytes(r.Recv), r.User, f.Status, Rules.FlagCol(fl), f.Path);
                // timeline: the 60 programs that sent the most (the table lists all)
                if (k++ < 60 || Rules.Strong(fl).Count > 0) c.Event(r.First, "SRU", r.Path, $"SRUM first activity in the window; sent {Cmd.Bytes(r.Sent)} in total");
                if (r.Sent >= 50L << 20 && !c.SignedOk(r.Path))
                {
                    // what the file is (an interpreter where none is installed, Defender detected it, ...), else the upload as context
                    var upFl = Rules.Strong(fl).Concat(c.MarksOf(r.Path)).ToList();
                    if (Rules.InterpreterOutside(r.Path, c.WinDir, Rules.HasUninstaller)) upFl.Add(Rules.InterpreterOutsideFlag);
                    if (Rules.Strong(upFl).Count == 0) upFl.Add("!upload");
                    c.Find(r.Last, $"{c.File(r.Path)} sent {Cmd.Bytes(r.Sent)} ({r.First:MM-dd} to {r.Last:MM-dd}, SRUM)", null, upFl.Distinct().ToList());
                }
            }
            if (staging > 0) c.Out.Comment($"Hidden: {Util.Plural(staging, "updater package", "updater packages")} staged by Edge, Brave, Google or Windows Update; -nowhitelist lists them.");
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
                var fl = Rules.DrivePath.IsMatch(path) ? c.WithLolbinCopy(path, Rules.Flags(path)) : Rules.Flags(path);
                var f = Rules.DrivePath.IsMatch(path) ? c.F(path) : (path, "-");
                var disp = f.Item1;
                bool unsigned = Ctx.BadSig(f.Item2);
                if (Rules.Whitelist && Rules.DrivePath.IsMatch(path) && Trusted(path) && !fl.Contains("!lolbin") && !unsigned) continue;
                if (Rules.Whitelist && !Rules.DrivePath.IsMatch(path)) continue;   // System, protected processes
                ct.Add(g.Key.ToString(), f.Item2, Rules.FlagCol(fl), disp, string.Join(", ", est), string.Join(", ", lis.Select(x => "port " + x)));
                if (est.Count > 0 && (fl.Contains("!lolbin") || (unsigned && !Trusted(path))))
                    c.Find(null, disp, $"connected to {string.Join(", ", est.Take(3))}", fl);
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
                if (hit.Count > 0 && (cat == "remote access" || cat == "tunnel / dynamic DNS" || cat == "victim ID in name"))
                    c.Find(null, $"DNS cache, {cat}: {string.Join(", ", hit)}", null, Rules.InfoFlag("!remote-access"));
            }
            if (!Rules.Whitelist)
                foreach (var n in names.Where(n => !Domains.Any(d => d.Match(n)))) dt.Add("-", n);
            c.Out.Comment($"{names.Count} names cached");
            dt.WriteTo(c.Out, "none of these");
        }
    }
}
