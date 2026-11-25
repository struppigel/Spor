using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace Spor.Modules
{
    /// <summary>
    /// RAT / remote access:
    ///  - Programs that used webcam or microphone (CapabilityAccessManager, all users): last use per program, newest Max programs
    ///  - Remote access tools (RMM): AnyDesk/TeamViewer connection logs and AnyDesk file transfers, ScreenConnect relay + Application
    ///    log events, Splashtop event logs, Radmin log, Atera account, NetSupport/MeshAgent/RustDesk server found in configs by content
    ///    (also renamed ones), other RMM folders: newest log/config files with lines containing public IPs. Times as written by the tool.
    /// </summary>
    class RemoteAccess : IModule
    {
        public string Id => "remote";
        public string Name => "REMOTE ACCESS";
        public string Description => "webcam and microphone use, remote access tools (AnyDesk, TeamViewer, ...)";

        static readonly Regex PubIp = new Regex(@"\b(?!(10|127|0)\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|2(2[4-9]|[3-5]\d)\.)\d{1,3}(\.\d{1,3}){3}\b", Util.RX);
        static readonly Regex Rmm = new Regex(@"anydesk|teamviewer|ultraviewer|zoho|screenconnect|connectwise|netsupport|rustdesk|splashtop|logmein|goto ?(assist|resolve|opener|mypc)|supremo|simplehelp|jwrapper|hoptodesk|awesun|aweray|dwagent|mesh ?agent|meshcentral|tactical ?rmm|atera|action1|ninjarmm|getscreen|ammyy|aeroadmin|remote ?utilities|vnc|radmin|rserver|rport|remotepc|syncro|pulseway", Util.RX);
        static readonly Regex CfgLine = new Regex(@"^\s*(GatewayAddress|SecondaryGateway|MeshName|MeshServer|rendezvous_server|custom-rendezvous-server|relay-server|api-server)\s*=", Util.RX);

        Ctx c;
        bool any;

        /// <summary>
        /// Remote access found (a tool, its logs, a camera in use): context for the case, in the SUMMARY with !remote-access. when: what
        /// the time is (file written, key changed), for the reader of this code only: like Ctx.Find(t, text, when), the line does not
        /// carry it (the SUMMARY's comment explains such times).
        /// </summary>
        void Found(DateTime? t, string text, string when = null) => c.Find(t, text, null, Rules.InfoFlag("!remote-access"));

        public void Execute(Ctx ctx)
        {
            c = ctx;
            Webcam(c.Hives);
            Rmms();
        }

        void Webcam(List<Hive> hives)
        {
            int max = c.Opt.Max;
            c.Out.Sub("Webcam and microphone: last use per desktop program (oldest first)");
            var cam = new List<(DateTime T, DateTime? E, string Cap, string User, string P)>();
            var pkg = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
            var roots = new List<(string User, RegistryKey Root, string Sub)> { ("", Registry.LocalMachine, "SOFTWARE") };
            roots.AddRange(hives.Select(h => (h.User, h.Root, "Software")));
            foreach (var r in roots)
                foreach (var cap in new[] { "webcam", "microphone" })
                {
                    try
                    {
                        using (var b = r.Root.OpenSubKey(r.Sub + @"\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\" + cap))
                        {
                            if (b == null) continue;
                            foreach (var n in b.GetSubKeyNames())
                                using (var s = b.OpenSubKey(n))
                                {
                                    if (s == null) continue;
                                    if (!n.Equals("NonPackaged", StringComparison.OrdinalIgnoreCase))
                                    {
                                        if (s.GetValue("LastUsedTimeStart") != null) pkg.Add(Regex.Replace(n, "_[a-z0-9]{13}$", "", Util.RX));
                                        continue;
                                    }
                                    foreach (var a in s.GetSubKeyNames())
                                        using (var x = s.OpenSubKey(a))
                                        {
                                            var t1 = Util.FtTime(x?.GetValue("LastUsedTimeStart")); var t2 = Util.FtTime(x?.GetValue("LastUsedTimeStop"));
                                            if (t1 == null) continue;
                                            cam.Add((t1.Value, t2, cap, r.User, a.Replace('#', '\\')));
                                        }
                                }
                        }
                    }
                    catch (Exception e) { c.Err.Add("ConsentStore " + cap + " " + r.User + ": " + e.Message); }
                }

            // the last use per program and device, in the time window (or still in use): years of video calls are no evidence
            var cg = cam.GroupBy(x => Regex.Replace(x.P, @"\\app-[\d.]+\\", @"\app-*\", Util.RX) + "\u0001" + x.Cap, Util.IC)
                        .Select(g => g.OrderByDescending(x => x.T).First())
                        .Where(x => x.T >= c.Since || x.E == null || x.E < x.T).OrderBy(x => x.T).ToList();
            foreach (var g in cg)
            {
                bool open = g.E == null || g.E < g.T;
                var until = open ? "in use now or not stopped cleanly" : "until " + g.E.Value.ToString(g.E.Value.Date == g.T.Date ? "HH:mm:ss" : Log.TimeFmt);
                c.Event(g.T, g.Cap == "webcam" ? "CAM" : "MIC", g.P, until);
                if (open) Found(g.T, g.Cap + " " + until + ": " + c.File(g.P));
            }
            var wt = new Table("@last use", "until", "device", "[user", "!status", "*program");
            foreach (var g in cg)
            {
                bool open = g.E == null || g.E < g.T; var f = c.F(g.P);
                wt.Add(Log.T(g.T), open ? "in use now or not stopped cleanly" : Log.T(g.E), g.Cap, g.User, f.Status, f.Path);
            }
            if (pkg.Count > 0) c.Out.Wrap("Store apps that used them (any time): ", pkg);
            wt.WriteTo(c.Out);
        }

        Table rt;            // remote access findings: one record per log/config/folder, log lines as continuation lines
        readonly Log after = new Log();   // event tables, written after the findings table

        void Tail(string tool, string f, string what, int n)
        {
            var l = Util.Lines(f); any = true;
            rt.Add(Log.T(File.GetLastWriteTimeUtc(f)), tool, c.F(f, false).Path, $"{l.Count} lines{what}");
            foreach (var x in l.Skip(Math.Max(0, l.Count - n)))
                rt.More("line", Regex.Replace(x.Trim(), @"\s{2,}|\t", " "));
        }

        void Events(string log, string xpath, int n, string title, string tool)
        {
            var q = new EventLogQuery(log, PathType.LogName, xpath) { ReverseDirection = true };
            var list = new List<EventRecord>();
            int older = 0;
            using (var rd = new EventLogReader(q))
            {
                for (EventRecord e; list.Count < n && (e = rd.ReadEvent()) != null;) list.Add(e);
                for (EventRecord e; (e = rd.ReadEvent()) != null; older++) e.Dispose();
            }
            if (list.Count == 0) return;
            any = true;
            after.Sub(title + (older > 0 ? $" (newest {list.Count} of {list.Count + older}; the rest are in the {log} event log)" : ""));
            var et = new Table("@time", "[event", "*message");
            Found(list[0].TimeCreated?.ToUniversalTime(), tool + ": " + list.Count + " events in " + log);
            foreach (var e in list.OrderBy(e => e.TimeCreated))
            {
                string msg;
                try { msg = e.FormatDescription(); } catch { msg = null; }
                if (string.IsNullOrEmpty(msg)) msg = string.Join(" ", e.Properties.Select(p => Convert.ToString(p.Value)));
                var t = e.TimeCreated?.ToUniversalTime();
                et.Add(Log.T(t), e.Id.ToString(), msg);
                c.Event(t, "RMM", null, text: $"{tool} event {e.Id}: {msg}");
                e.Dispose();
            }
            et.WriteTo(after);
        }

        static DateTime? Local(string s, params string[] fmt) =>
            DateTime.TryParseExact(s.Trim(), fmt, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.AssumeLocal, out var t)
                ? t.ToUniversalTime() : (DateTime?)null;

        void Rmms()
        {
            int max = c.Opt.Max;
            string pd = Ctx.Env("ProgramData"), pf = Ctx.Env("ProgramFiles"), pf86 = Ctx.Env("ProgramFiles(x86)");
            var dirs = new[] { pd, pf, pf86, Path.Combine(c.WinDir, "Temp") }
                .Concat(c.Profiles.SelectMany(p => new[] { Path.Combine(p.Path, @"AppData\Roaming"), Path.Combine(p.Path, @"AppData\Local"), Path.Combine(p.Path, @"AppData\Local\Temp") }))
                .Where(d => !string.IsNullOrEmpty(d)).Distinct(Util.IC).ToList();
            c.Out.Sub("Remote access tools", $"Connection logs, file transfers and the server/account they report to (last {max} entries each).\n" +
                "time = file last written; line: = log line (times as the tool wrote them); setting: = server/account setting");
            rt = new Table("@time", "[tool", "*source", "=what");
            any = false;

            // AnyDesk: connection_trace = direction | time | auth (Passwd, Token = saved unattended access, User = accepted by the user) | remote ID
            var ad = new List<string> { Path.Combine(pd, "AnyDesk") };
            try { if (Directory.Exists(ad[0])) ad.AddRange(Directory.GetDirectories(ad[0], "ad_*")); } catch { }
            ad.AddRange(c.Profiles.Select(p => Path.Combine(p.Path, @"AppData\Roaming\AnyDesk")));
            foreach (var d in ad)
            {
                if (!Directory.Exists(d)) continue;
                var f = Path.Combine(d, "connection_trace.txt");
                if (File.Exists(f))
                    try
                    {
                        Tail("AnyDesk", f, "; direction | time | auth (Token = saved access) | remote ID", max);
                        int n = 0;
                        foreach (var l in Util.Lines(f))
                        {
                            var m = Regex.Match(l, @"^\s*(Incoming|Outgoing)\s+(\d{4}-\d{2}-\d{2}),?\s+(\d{1,2}:\d{2})\s+(\S+)\s+(\d+)", Util.RX);
                            if (!m.Success) continue;
                            n++;
                            c.Event(Local(m.Groups[2].Value + " " + m.Groups[3].Value, "yyyy-MM-dd H:mm"), "RMM", null,
                                text: $"AnyDesk {m.Groups[1].Value.ToLowerInvariant()} connection, remote ID {m.Groups[5].Value}, auth {m.Groups[4].Value}");
                        }
                        Found(File.GetLastWriteTimeUtc(f), $"AnyDesk connection log: {n} connections ({c.File(f, false)})", "file written");
                    }
                    catch (Exception e) { c.Err.Add("AnyDesk " + f + ": " + e.Message); }
                f = Path.Combine(d, "file_transfer_trace.txt");
                if (File.Exists(f))
                    try { Tail("AnyDesk", f, " (file transfers)", max); Found(File.GetLastWriteTimeUtc(f), "AnyDesk file transfer log: " + c.File(f, false), "file written"); }
                    catch (Exception e) { c.Err.Add("AnyDesk " + f + ": " + e.Message); }
                string[] traces = new string[0];
                try { traces = Directory.GetFiles(d, "*.trace"); } catch { }
                foreach (var tf in traces)
                {
                    try
                    {
                        var m = Util.Lines(tf).Where(x => Regex.IsMatch(x, "Logged in from|Incoming session request|Accepting from|Client-ID:")).ToList();
                        var id = m.Where(x => x.Contains("Client-ID:")).ToList(); m = m.Where(x => !x.Contains("Client-ID:")).ToList();
                        if (id.Count > 0) { any = true; rt.Add(Log.T(File.GetLastWriteTimeUtc(tf)), "AnyDesk", c.F(tf, false).Path, "own AnyDesk ID " + Regex.Replace(Regex.Replace(id[id.Count - 1], @".*Client-ID:\s*", ""), @"\D+$", "")); }
                        if (m.Count > 0)
                        {
                            any = true; rt.Add(Log.T(File.GetLastWriteTimeUtc(tf)), "AnyDesk", c.F(tf, false).Path, $"{m.Count} incoming connection lines");
                            foreach (var x in m.Skip(Math.Max(0, m.Count - max))) rt.More("line", Regex.Replace(x.Trim(), @"\s{2,}", " "));
                        }
                    }
                    catch (Exception e) { c.Err.Add("AnyDesk " + tf + ": " + e.Message); }
                }
            }

            // TeamViewer: remote ID | remote name | start | end | local user | type
            foreach (var d in new[] { pf, pf86 }.Where(x => !string.IsNullOrEmpty(x)).Distinct(Util.IC))
            {
                var f = Path.Combine(d, @"TeamViewer\Connections_incoming.txt");
                if (!File.Exists(f)) continue;
                try
                {
                    var l = Util.Lines(f); any = true;
                    rt.Add(Log.T(File.GetLastWriteTimeUtc(f)), "TeamViewer", c.F(f, false).Path, $"{l.Count} connections");
                    string[] tvn = { "remote ID", "name", "start", "end", "local user", "type" };
                    foreach (var x in l.Skip(Math.Max(0, l.Count - max)))
                        rt.More("connection", string.Join("; ", x.Trim().Split('\t').Take(6).Select((v, i) => tvn[i] + " " + (v.Trim().Length > 0 ? v.Trim() : "-"))));
                    foreach (var x in l)
                    {
                        var col = x.Trim().Split('\t');
                        if (col.Length < 3) continue;
                        c.Event(Local(col[2], "dd-MM-yyyy HH:mm:ss", "dd-MM-yyyy HH:mm"), "RMM", null,
                            text: $"TeamViewer incoming connection, remote ID {col[0]}{(col.Length > 1 && col[1].Trim().Length > 0 ? " (" + col[1].Trim() + ")" : "")}");
                    }
                    Found(File.GetLastWriteTimeUtc(f), $"TeamViewer: {l.Count} incoming connections ({c.File(f, false)})", "file written");
                }
                catch (Exception e) { c.Err.Add("TeamViewer: " + e.Message); }
            }

            // ScreenConnect: relay host from the service command line (h=...&p=...), connections from the Application log (100 connected, 101 disconnected, 201 file transfer)
            try
            {
                using (var svc = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services"))
                    foreach (var n in svc.GetSubKeyNames().Where(x => x.IndexOf("ScreenConnect", StringComparison.OrdinalIgnoreCase) >= 0))
                        using (var k = svc.OpenSubKey(n))
                        {
                            var ip = Convert.ToString(k?.GetValue("ImagePath")) ?? ""; any = true;
                            var h = Regex.Match(ip, @"[?&]h=([^&""\s]+)"); var p = Regex.Match(ip, @"[?&]p=(\d+)");
                            var relay = $"relay {(h.Success ? h.Groups[1].Value : "?")}:{(p.Success ? p.Groups[1].Value : "?")}";
                            rt.Add(Log.T(Native.LastWrite(k)), "ScreenConnect", "service " + n, relay);
                            Found(Native.LastWrite(k), $"ScreenConnect service \"{n}\": {relay}", "key changed");
                        }
            }
            catch (Exception e) { c.Err.Add("ScreenConnect service: " + e.Message); }
            try
            {
                List<string> pn;
                using (var el = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\EventLog\Application"))
                    pn = el?.GetSubKeyNames().Where(x => x.StartsWith("ScreenConnect", StringComparison.OrdinalIgnoreCase)).ToList() ?? new List<string>();
                if (pn.Count > 0)
                {
                    var prov = string.Join(" or ", pn.Select(x => "@Name='" + x.Replace("'", "&apos;") + "'"));
                    Events("Application", $"*[System[Provider[{prov}] and (EventID=100 or EventID=101 or EventID=201)]]", max * 3, "ScreenConnect events (Application log)", "ScreenConnect");
                }
            }
            catch (Exception e) { c.Err.Add("ScreenConnect events: " + e.Message); }

            // Splashtop: own event logs
            foreach (var ln in new[] { "Splashtop-Splashtop Streamer-Remote Session/Operational", "Splashtop-Splashtop Streamer-Status/Operational" })
            {
                try { Events(ln, "*", max, "Splashtop: " + ln, "Splashtop"); } catch { }   // log missing = not installed
            }

            // Radmin server log (HTML)
            foreach (var f in new[] { Path.Combine(c.WinDir, @"System32\rserver30\Radm_log.htm"), Path.Combine(c.WinDir, @"SysWOW64\rserver30\Radm_log.htm") })
            {
                if (!File.Exists(f)) continue;
                try
                {
                    var t = Regex.Replace(Util.ReadText(f), "<[^>]*>", "\n").Replace("&lt;", "<").Replace("&gt;", ">").Replace("&amp;", "&");
                    var l = t.Split('\n').Select(x => x.Trim()).Where(x => x.Length > 0 && !Regex.IsMatch(x, "is started|Listening for incoming|Radmin Server Log", Util.RX)).ToList();
                    any = true; rt.Add(Log.T(File.GetLastWriteTimeUtc(f)), "Radmin", c.F(f, false).Path, $"{l.Count} lines without start messages");
                    foreach (var x in l.Skip(Math.Max(0, l.Count - max))) rt.More("line", x);
                    Found(File.GetLastWriteTimeUtc(f), "Radmin server log: " + c.File(f, false), "file written");
                }
                catch (Exception e) { c.Err.Add("Radmin: " + e.Message); }
            }

            // Atera: account the agent reports to
            try
            {
                using (var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\ATERA Networks\AlphaAgent"))
                    if (k != null)
                    {
                        any = true;
                        var line = $"account {k.GetValue("IntegratorLogin")}, AccountId {k.GetValue("AccountId")}, AgentId {k.GetValue("AgentId")}";
                        rt.Add(Log.T(Native.LastWrite(k)), "Atera", @"HKLM\SOFTWARE\ATERA Networks\AlphaAgent", line);
                        Found(Native.LastWrite(k), "Atera agent: " + line, "key changed");
                    }
            }
            catch { }

            // Server/account in configs, found by content (malware renames them): NetSupport *.ini with GatewayAddress, MeshAgent *.msh, RustDesk/HopToDesk *.toml
            var sw = System.Diagnostics.Stopwatch.StartNew(); int nchk = 0;
            var cfg = new HashSet<string>(Util.IC);
            foreach (var r in dirs.Concat(new[] { Path.Combine(c.WinDir, @"ServiceProfiles\LocalService\AppData\Roaming"), Ctx.Env("PUBLIC") }))
            {
                if (string.IsNullOrEmpty(r) || !Directory.Exists(r)) continue;
                foreach (var f in Util.Walk(r, 3, "*.ini", "*.msh", "*.toml").Where(x => Regex.IsMatch(x.Extension, @"^\.(ini|msh|toml)$", Util.RX) && x.Length < 200 * 1024))
                {
                    nchk++;
                    if (cfg.Contains(f.FullName)) continue;
                    try
                    {
                        var t = Util.ReadText(f.FullName);
                        var hit = Regex.Split(t, "\r?\n").Where(x => CfgLine.IsMatch(x)).ToList();
                        if (hit.Count == 0) continue;
                        cfg.Add(f.FullName); any = true;
                        var cf = c.F(f.FullName);
                        rt.Add(Log.T(f.LastWriteTimeUtc), "config", Log.Item(cf.Path, cf.Status), "server/account settings");
                        foreach (var x in hit) rt.More("setting", x.Trim());
                        bool silent = Regex.IsMatch(t, @"(?m)^\s*silent\s*=\s*1", Util.RX);
                        if (silent) rt.More("setting", "silent=1 (NetSupport client hidden from the user)");
                        c.Event(f.LastWriteTimeUtc, "RMM", f.FullName, "server config: " + Util.Clip(hit[0].Trim(), 80));
                        Found(f.LastWriteTimeUtc, "remote access config " + c.File(f.FullName) + ": " + Util.Clip(hit[0].Trim(), 100) + (silent ? ", silent=1" : ""), "file written");
                    }
                    catch { }
                }
            }
            double cfgsec = sw.Elapsed.TotalSeconds;

            // Other RMM tools: newest log/config files in their folders, with lines that contain public IP addresses
            foreach (var r in dirs)
            {
                string[] sub;
                try { sub = Directory.GetDirectories(r); } catch { continue; }
                foreach (var d in sub)
                {
                    var name = Path.GetFileName(d);
                    if (!Rmm.IsMatch(name) || Regex.IsMatch(name, "anydesk|teamviewer", Util.RX)) continue;
                    try
                    {
                        if ((new DirectoryInfo(d).Attributes & FileAttributes.ReparsePoint) != 0) continue;
                        var all = Util.Walk(d, 3, "*.log", "*.txt", "*.trace", "*.htm", "*.xml", "*.json", "*.conf", "*.cfg", "*.ini", "*.toml", "*.exe", "*log*").ToList();
                        var fs = all.Where(x => !x.Extension.Equals(".exe", StringComparison.OrdinalIgnoreCase)).OrderByDescending(x => x.LastWriteTimeUtc).ToList();
                        var exe = all.Where(x => x.Extension.Equals(".exe", StringComparison.OrdinalIgnoreCase)).ToList();
                        if (fs.Count == 0 && exe.Count == 0) continue;
                        any = true;
                        rt.Add(fs.Count > 0 ? Log.T(fs[0].LastWriteTimeUtc) : "-", "RMM folder", c.RealCase(d) + "\\", $"{exe.Count} exe, {fs.Count} log/config files");
                        Found(fs.Count > 0 ? fs[0].LastWriteTimeUtc : (DateTime?)null, $"remote access tool folder {c.RealCase(d)}\\", "file written");
                        if (fs.Count > 0) c.Event(fs[0].LastWriteTimeUtc, "RMM", null, text: $"{c.RealCase(d)}\\: newest log/config written ({fs[0].Name})");
                        foreach (var x in exe) rt.More("exe", c.FF(x.FullName));
                        foreach (var f in fs.Skip(3)) rt.More("file", $"{Log.T(f.LastWriteTimeUtc)} {f.FullName}");
                        foreach (var f in fs.Take(3))
                        {
                            var ipl = Util.Lines(f.FullName).Where(x => PubIp.IsMatch(x)).ToList();
                            rt.More("file", $"{Log.T(f.LastWriteTimeUtc)} {f.FullName} => {ipl.Count} lines with public IPs");
                            foreach (var x in ipl.Skip(Math.Max(0, ipl.Count - 5))) rt.More("ip line", Regex.Replace(x.Trim(), @"\s{2,}", " "));
                        }
                    }
                    catch (Exception e) { c.Err.Add("RMM folder " + d + ": " + e.Message); }
                }
            }
            c.Out.Comment($"Checked {nchk} .ini/.msh/.toml files for server settings ({cfgsec:N1} s; with the RMM folder scan {sw.Elapsed.TotalSeconds:N1} s).");
            rt.WriteTo(c.Out, "no AnyDesk, TeamViewer, ScreenConnect, Splashtop, Radmin, Atera, NetSupport, MeshAgent, RustDesk or other RMM traces");
            c.Out.Lines.AddRange(after.Lines);
        }
    }
}
