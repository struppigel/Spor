using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace Spor.Modules
{
    /// <summary>
    /// Execution evidence besides prefetch and Amcache:
    ///  - PCA (Win11 22H2+, C:\Windows\appcompat\pca): programs launched from Explorer, with launch time.
    ///  - UserAssist (per user): programs started from Explorer/Start menu, with run count and last run time.
    ///  - BAM (per user, kept about a week): last run time of programs.
    ///  - ShimCache (AppCompatCache): files Windows checked for compatibility, newest first. Time = file's modification time
    ///    (often the drop time for malware), not the run time. Saved at shutdown, so the current session is missing.
    ///  - Compatibility Assistant store (per user): programs that ran at some point, no times; only listed if the file is gone now.
    /// </summary>
    class ExecEvidence : IModule
    {
        public string Id => "exec";
        public string Name => "EXECUTION EVIDENCE";
        public string Description => "PCA, UserAssist, BAM, ShimCache, Compatibility Assistant";

        /// <summary>A forward / reverse delta of a component in WinSxS (...\amd64_..._powershell-exe_...\f\powershell.exe): no signature of its own.</summary>
        internal static readonly Regex WinSxsDelta = new Regex(@"^[a-z]:\\windows\\winsxs\\[^\\]+\\[fr]\\[^\\]+$", Util.RX);


        Ctx c;
        Regex noise;
        readonly Dictionary<string, int> qk = new Dictionary<string, int>(Util.IC);

        class Row { public int N; public DateTime? M; public string P, User; public List<string> F = new List<string>(); public int More; public string Names; }

        public void Execute(Ctx ctx)
        {
            c = ctx; noise = Rules.Noise(Whitelist.Noise("exec"));
            var hives = c.Hives;
            void AddEv(DateTime? t, string src, string user, string p, string x)
            {
                if (!t.HasValue || t.Value < c.Since || !Keep(p)) return;
                var extra = string.Join(" ", new[] { c.MultiUser ? user : "", x }.Where(s => !string.IsNullOrEmpty(s)));
                c.Event(t, src, p, extra.Length > 0 ? (src == "PCA" ? "PCA: " : src + " ") + extra : null);
            }

            // ---- PCA ----
            int npca = 0;
            var pca = Path.Combine(c.WinDir, @"appcompat\pca");
            string[] pcaFiles = new string[0];
            try { if (Directory.Exists(pca)) pcaFiles = Directory.GetFiles(pca, "Pca*.txt"); } catch (Exception e) { c.Err.Add("PCA: " + e.Message); }
            foreach (var f in pcaFiles)
            {
                try
                {
                    bool dic = Path.GetFileName(f).StartsWith("PcaAppLaunchDic", StringComparison.OrdinalIgnoreCase);
                    foreach (var l in Regex.Split(Util.ReadText(f), "\r?\n"))
                    {
                        if (l.Trim().Length == 0) continue;
                        var col = l.Split('|');
                        if (dic)
                        {
                            if (col.Length < 2) continue;
                            npca++;
                            AddEv(PcaTime(col[col.Length - 1]), "PCA", "", c.Long(PcaPath(string.Join("|", col.Take(col.Length - 1)))), "");
                        }
                        else if (col.Length >= 3)   // PcaGeneralDb: time|status|path|description|vendor|version|programId|message
                        {
                            npca++;
                            var msg = col.Length >= 8 ? Regex.Replace(col[7].Trim(), "^PCA resolve is called.*", "") : "";   // keep exit codes / install failures
                            AddEv(PcaTime(col[0]), "PCA", "", c.Long(PcaPath(col[2])), msg);
                        }
                    }
                }
                catch (Exception e) { c.Err.Add("PCA " + Path.GetFileName(f) + ": " + e.Message); }
            }

            // ---- UserAssist ----
            int nua = 0;
            foreach (var h in hives)
            {
                try
                {
                    using (var k = h.Root.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count"))
                    {
                        if (k == null) continue;
                        foreach (var v in k.GetValueNames())
                        {
                            if (!(k.GetValue(v) is byte[] d) || d.Length < 68) continue;
                            var p = UaPath(Rot13(v), h.P.Path); if (p == null) continue;
                            nua++; int cnt = BitConverter.ToInt32(d, 4);
                            AddEv(Util.FtTime(BitConverter.ToInt64(d, 60)), "UA", h.User, c.Long(p), cnt > 0 ? cnt + "x" : "");
                        }
                    }
                }
                catch (Exception e) { c.Err.Add("UserAssist " + h.User + ": " + e.Message); }
            }

            // ---- BAM ----
            var dev = new Dictionary<string, string>(Util.IC);
            foreach (var d in DriveInfo.GetDrives()) { try { var n = d.Name.TrimEnd('\\'); var t = Native.DosDevice(n); if (t != null) dev[t] = n; } catch { } }
            int nbam = 0;
            foreach (var bk in new[] { @"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings", @"SYSTEM\CurrentControlSet\Services\bam\UserSettings" })
            {
                try
                {
                    using (var k = Registry.LocalMachine.OpenSubKey(bk))
                    {
                        if (k == null) continue;
                        foreach (var sid in k.GetSubKeyNames())
                            using (var s = k.OpenSubKey(sid))
                            {
                                if (s == null) continue;
                                var user = c.UserOf(sid);
                                foreach (var v in s.GetValueNames())
                                {
                                    var m = Regex.Match(v, @"^(\\Device\\[^\\]+)(\\.+)$", Util.RX);
                                    if (!m.Success) continue;
                                    if (!(s.GetValue(v) is byte[] d) || d.Length < 8) continue;
                                    var p = dev.TryGetValue(m.Groups[1].Value, out var dl) ? c.Long(dl + m.Groups[2].Value) : v;
                                    nbam++; AddEv(Util.FtTime(BitConverter.ToInt64(d, 0)), "BAM", user, p, "");
                                }
                            }
                    }
                }
                catch (Exception e) { c.Err.Add("BAM: " + e.Message); }
            }

            // ---- ShimCache ----
            var shim = new List<Row>(); int nshim = 0; string shimNote = "";
            try
            {
                using (var k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache"))
                {
                    var raw = k?.GetValue("AppCompatCache") as byte[];
                    var all = Shim(raw); nshim = all.Count;
                    if (raw != null && raw.Length >= 4 && raw.Length <= BitConverter.ToInt32(raw, 0))
                        shimNote = $"ShimCache is empty (only the {raw.Length}-byte header): Windows saves it at a full shutdown or restart; with Fast Startup, a shutdown does not count.";
                    var seen = new HashSet<string>(Util.IC);
                    foreach (var e in all)
                    {
                        if (e.P.IndexOf('\t') >= 0) continue;   // packaged (Store) apps
                        var p = c.Long(e.P);
                        if (!seen.Add(p)) continue;
                        var f = c.WithLolbinCopy(p, Rules.Flags(p));   // a LOLBin copy outside its folders: also older entries
                        if (f.Count == 0 && (!e.M.HasValue || e.M.Value < c.Since)) continue;   // only files modified in the last Days days (+ flagged)
                        if (!Keep(p)) continue;
                        shim.Add(new Row { N = e.N, P = p, M = e.M, F = f });
                    }
                }
            }
            catch (Exception e) { c.Err.Add("ShimCache: " + e.Message); }

            // ---- Compatibility Assistant store ----
            var cas = new List<Row>(); int ncas = 0;
            foreach (var h in hives)
            {
                try
                {
                    using (var k = h.Root.OpenSubKey(@"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store"))
                    {
                        if (k == null) continue;
                        foreach (var v in k.GetValueNames()) { ncas++; var p = c.Long(v); if (Keep(p)) cas.Add(new Row { P = p, User = h.User }); }
                    }
                }
                catch (Exception e) { c.Err.Add("Compatibility Assistant " + h.User + ": " + e.Message); }
            }

            // ---- ShimCache to the timeline: per folder the newest PerDir files, then one "+N more" line ----
            // Older entries only go to the summary if flagged. A LOLBin alone is no finding here: ShimCache proves no run on Windows 10/11,
            // and a validly signed Windows tool in its own folder that was modified before the time window is a Windows update.
            // A LOLBin copy elsewhere, or one with a bad signature, is still a finding.
            int oldLol = 0;
            var olderFlagged = new List<(DateTime? M, string P, List<string> F)>();   // their section lines (the SUMMARY's "details in the sections below")
            foreach (var x in Grouped(shim, r => r.N.ToString("D8")))
            {
                if (x.More > 0) c.Event(x.M, "SC", null, text: Rules.Fix(c.RealCase(x.P.TrimEnd('\\'))) + "\\ => " + Util.Plural(x.More, "more file", "more files") + " modified in this folder: " +Rules.Fix(x.Names));
                else if (Rules.Whitelist && Rules.Strong(x.F).Count == 0 && Rules.InTrustedLocation(x.P) && (c.SignedOk(x.P) || WinSxsDelta.IsMatch(x.P))) oldLol++;   // also inside the window: a Windows update
                else if (x.M.HasValue && x.M.Value >= c.Since)
                {
                    if (Rules.DrivePath.IsMatch(x.P ?? "")) c.Event(x.M, "SC", x.P, null, x.F);
                    else c.Event(x.M, "SC", null, null, x.F, text: "ShimCache entry without a folder: " + Rules.Fix(x.P));
                }
                // flagged, older: Correlate writes it, or makes it a detail of later evidence when the file is a copy (FoldCopiedShimCache)
                else
                {
                    c.PendingShim.Add((x.M, c.Module, x.P, c.File(x.P), "ShimCache: file modified", x.F));
                    if (Rules.Strong(x.F).Count > 0) olderFlagged.Add((x.M, x.P, x.F));
                }
            }
            if (olderFlagged.Count > 0)
            {
                c.Out.Sub("ShimCache: flagged files modified before the time window", "time = the file's modification time ShimCache recorded (a copy keeps the original's)");
                var st = new Table("@modified", "!status", "<flags", "*file");
                foreach (var x in olderFlagged.OrderBy(x => x.M))
                {
                    var f = c.F(x.P);
                    st.Add(Log.T(x.M), f.Status, Rules.FlagCol(x.F), f.Path);
                }
                st.WriteTo(c.Out);
            }

            var creations = ProcessCreations();

            // ---- details ----
            var o = c.Opt;
            c.Out.Comment(creations);
            c.Out.Comment($"Read PCA {npca}, UserAssist {nua}, BAM {nbam}, ShimCache {nshim}, Compatibility Assistant {ncas}");
            var notes = new List<string>();
            if (oldLol > 0) notes.Add($"Hidden: {oldLol} ShimCache entries of validly signed LOLBins in trusted locations (Windows updates; -nowhitelist lists them).");
            if (shimNote.Length > 0) notes.Add(shimNote.Trim());
            if (notes.Count > 0) c.Out.Comment(string.Join(" ", notes));
            c.Out.Sub("Compatibility Assistant: programs that ran at some point and are gone now", "No times are stored. Per folder the first " + o.PerDir + " one per line, then the other file names on one line.");
            var cr = cas.Where(x => Regex.IsMatch(x.P, @"^[a-z]:\\", Util.RX) && !File.Exists(x.P))
                        .Select(x => new Row { P = x.P, User = x.User, F = Rules.Flags(x.P) }).ToList();
            var ct = new Table("[user", "!status", "<flags", "*program");
            foreach (var x in Grouped(cr, r => r.P).OrderBy(r => Util.Folder(r.P), StringComparer.OrdinalIgnoreCase).ThenBy(r => r.More > 0).ThenBy(r => r.P, StringComparer.OrdinalIgnoreCase))
            {
                if (x.More > 0) { ct.Add("-", "-", "-", $"{Rules.Fix(c.RealCase(x.P.TrimEnd('\\')))}\\ => {x.More} more: {Rules.Fix(x.Names)}"); continue; }
                var f = c.F(x.P);
                ct.Add(x.User ?? "-", f.Status, Rules.FlagCol(x.F), f.Path);
                if (Rules.Strong(x.F).Count > 0) c.Find(null, c.File(x.P), "Compatibility Assistant: ran at some point", x.F);
            }
            ct.WriteTo(c.Out);
            c.Out.Hidden(qk, "entries");
        }

        internal sealed class Creation { public DateTime T; public string Src, Pid, ParentPid, Image, Parent, Cmd, ParentCmd; }

        /// <summary>
        /// (pure) The first pass over process creation events: the proxy-execution events (a launcher among the creating processes, up to
        /// 4 levels, or a launcher itself pointed at a program outside Windows and Program Files that runs as a process of its own:
        /// cmd /c call &lt;exe&gt;, pcalua -a, ...), and their creators up to 4 levels, which the timeline keeps too. `parentOf` finds an
        /// event's creating event, `image` gives an event's program as a long path.
        /// </summary>
        internal static (HashSet<Creation> Proxy, HashSet<Creation> Creators) ProxyChains(
            IEnumerable<Creation> events, Func<Creation, Creation> parentOf, Func<string, string> image)
        {
            var proxies = new HashSet<Creation>();
            var creators = new HashSet<Creation>();
            foreach (var x in events)
            {
                var img = image(x.Image);
                var target = Rules.ProxyLaunchTarget(img, x.Cmd);
                bool proxy = target != null && Rules.LaunchesProcess(img, target);
                var cur = x;
                for (int i = 0; i < 4 && !proxy; i++)
                {
                    var p = parentOf(cur);
                    var pImage = p?.Image ?? (i == 0 ? x.Parent : null);
                    var pCmd = p?.Cmd ?? (i == 0 ? x.ParentCmd : null);
                    if (string.IsNullOrEmpty(pImage)) break;
                    proxy = Rules.ProxyExec(image(pImage), pCmd, img);
                    if (p == null) break;
                    cur = p;
                }
                if (!proxy) continue;
                proxies.Add(x);
                cur = x;
                for (int i = 0; i < 4 && (cur = parentOf(cur)) != null; i++) creators.Add(cur);
            }
            return (proxies, creators);
        }

        /// <summary>A PID from an event: 4688 writes hex ("0x1d4"), Sysmon decimal. Null if neither.</summary>
        internal static int? Pid(string s)
        {
            if (string.IsNullOrEmpty(s)) return null;
            s = s.Trim();
            if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                return int.TryParse(s.Substring(2), System.Globalization.NumberStyles.HexNumber, null, out var h) ? h : (int?)null;
            return int.TryParse(s, out var d) ? d : (int?)null;
        }

        const int MaxCreations = 20000;
        const string SysmonLog = "Microsoft-Windows-Sysmon/Operational";

        /// <summary>
        /// Process creation events in the time window: Security 4688 (needs process creation auditing; the command line only with its
        /// policy) and Sysmon event 1. Launches by LOLBins or interpreters, or of programs outside trusted locations, go to the timeline
        /// (4688, SYSMON), with !proxy-exec from the creating processes found in the events themselves; a proxy-execution event brings
        /// its creators (up to 4 levels). Catches proxy-execution chains when Prefetch is off, not written yet, or deleted. Spor turns
        /// nothing on. Returns the comment for the section.
        /// </summary>
        string ProcessCreations()
        {
            var list = new List<Creation>();
            var err = new List<string>();
            int n4688 = 0, nSysmon = 0;
            var sec = Ev.Fields("NewProcessId", "ProcessId", "NewProcessName", "ParentProcessName", "CommandLine");
            foreach (var e in Ev.Query("Security", "EventID=4688", c.Since, MaxCreations, err))
                using (e)
                {
                    var d = Ev.Values(e, sec, 5);
                    n4688++;
                    list.Add(new Creation
                    {
                        T = e.TimeCreated?.ToUniversalTime() ?? DateTime.MinValue, Src = "4688", Pid = d[0]?.ToLowerInvariant(),
                        ParentPid = d[1]?.ToLowerInvariant(), Image = d[2], Parent = d[3], Cmd = d[4],
                    });
                }
            bool sysmon = false;
            try { sysmon = System.Diagnostics.Eventing.Reader.EventLogSession.GlobalSession.GetLogNames().Contains(SysmonLog, StringComparer.OrdinalIgnoreCase); } catch { }
            var sys = Ev.Fields("ProcessId", "ParentProcessId", "Image", "ParentImage", "CommandLine", "ParentCommandLine");
            if (sysmon)
                foreach (var e in Ev.Query(SysmonLog, "EventID=1", c.Since, MaxCreations, err))
                    using (e)
                    {
                        var d = Ev.Values(e, sys, 6);
                        nSysmon++;
                        list.Add(new Creation
                        {
                            T = e.TimeCreated?.ToUniversalTime() ?? DateTime.MinValue, Src = "SYSMON", Pid = d[0], ParentPid = d[1],
                            Image = d[2], Parent = d[3], Cmd = d[4], ParentCmd = d[5],
                        });
                    }
            bool capped = err.Any(x => x.Contains("more than"));
            bool securityUnreadable = err.Any(x => x.StartsWith("Security:"));
            c.Err.AddRange(err.Where(x => !x.Contains("more than")));
            if (n4688 == 0 && !sysmon)
                return securityUnreadable ? "Process creation events: the Security log could not be read, and there is no Sysmon."
                                          : "No process creation auditing and no Sysmon: program starts only from Prefetch, BAM and Amcache.";

            // the creating process of an event, from the events themselves: PIDs are reused, so the newest creation before the child
            var byPid = list.Where(x => x.Pid != null).GroupBy(x => x.Src + "|" + x.Pid).ToDictionary(g => g.Key, g => g.OrderBy(x => x.T).ToList());
            Creation ParentOf(Creation x) =>
                x.ParentPid != null && byPid.TryGetValue(x.Src + "|" + x.ParentPid, out var cands) ? cands.LastOrDefault(p => p.T <= x.T && p != x) : null;
            int kept = 0;
            foreach (var x in list.Where(x => !string.IsNullOrEmpty(x.Image)))
                if (Pid(x.Pid) is int pid) c.ProcessStarts.Add((pid, x.T, c.Long(x.Image)));
            // first pass (ProxyChains): proxy execution and the creators of those events, which are kept too. A launcher pointed at a
            // folder (forfiles /p) or a batch file (cmd /c call x.bat) is kept by ProcessEventKept, unflagged.
            var creations = list.Where(x => !string.IsNullOrEmpty(x.Image) && x.T >= c.Since).ToList();
            var (proxies, creators) = ProxyChains(creations, ParentOf, c.Long);
            foreach (var x in creations)
            {
                var image = c.Long(x.Image);
                bool proxy = proxies.Contains(x);
                var parent = !string.IsNullOrEmpty(x.Parent) ? c.Long(x.Parent) : ParentOf(x)?.Image;
                if (!string.IsNullOrEmpty(parent) && Rules.DrivePath.IsMatch(parent) && !Rules.InTrustedLocation(parent))
                    c.Launches.Add((c.RealCase(parent), c.RealCase(image), x.Cmd, x.T));
                if (!creators.Contains(x) && !Rules.ProcessEventKept(image, parent, x.Cmd, proxy)) continue;
                kept++;
                var details = "parent " + (string.IsNullOrEmpty(parent) ? "unknown" : Util.Leaf(parent)) +
                              (string.IsNullOrEmpty(x.Cmd) ? "" : "; command line " + Rules.Fix(Util.Clip(x.Cmd)));
                c.Event(x.T, x.Src, image, details, proxy ? new List<string> { "!proxy-exec" } : null, pid: Pid(x.Pid));
            }
            return $"Process creation events: Security 4688 {n4688}" + (sysmon ? $", Sysmon 1 {nSysmon}" : "") + (capped ? $" (only the newest {MaxCreations} per log)" : "") +
                   $"; {kept} launches by LOLBins or interpreters, of programs outside trusted locations, or in a proxy-execution chain, are in the timeline (4688, SYSMON).";
        }

        /// <summary>Per folder: flagged rows + the first PerDir others, then a '(+N more)' row.</summary>
        List<Row> Grouped(List<Row> rows, Func<Row, string> order)
        {
            var res = new List<Row>(); int per = c.Opt.PerDir;
            foreach (var g in rows.GroupBy(r => Util.Folder(r.P), Util.IC))
            {
                // entries without a folder (ShimCache keeps some as a bare name or "SIGN.IE=... name"): each on its own line, never grouped
                if (string.IsNullOrEmpty(g.Key)) { res.AddRange(g); continue; }
                res.AddRange(g.Where(r => r.F.Count > 0));
                var rest = g.Where(r => r.F.Count == 0).OrderBy(order, StringComparer.OrdinalIgnoreCase).ToList();
                res.AddRange(rest.Take(per));
                if (rest.Count > per) res.Add(new Row { N = rest[per].N, M = rest.Skip(per).Max(r => r.M), P = g.Key + "\\", More = rest.Count - per,
                                                        Names = string.Join(", ", rest.Skip(per).Select(r => Util.Leaf(r.P))) });
            }
            return res;
        }

        /// <summary>2 = show, 1 = known noise (counted), 0 = trusted (ignored)</summary>
        int Hot(string p)
        {
            var m = Rules.DrivePath.Match(p);
            if (!m.Success) return 2;
            var d = m.Groups[1].Value; var rel = m.Groups[2].Value;
            if (Rules.OddChars(rel) || Rules.DoubleExt(rel) || Rules.Disg.IsMatch(rel)) return 2;
            if (!Rules.Whitelist) return 2;
            // programs that ran: noise folders and trusted locations hide only validly signed executables
            if (noise.IsMatch(rel)) return c.SignedOk(p) ? 1 : 2;   // before Risky: installer engines (WiX Burn) unpack into Windows\Temp
            if (!d.Equals(c.SystemDrive, StringComparison.OrdinalIgnoreCase) || Rules.Risky.IsMatch(rel)) return 2;
            if (Rules.Trusted.IsMatch(rel)) return c.SignedOk(p) ? 0 : 2;
            return 2;
        }

        string NoiseKey(string p)
        {
            string d = "", r = p;
            var m = Rules.DrivePath.Match(p);
            if (m.Success) { d = m.Groups[1].Value; r = m.Groups[2].Value; }
            var n = noise.Match(r);
            var k = d + (n.Success ? r.Substring(0, n.Index + n.Length) : r);
            k = Regex.Replace(k, @"\\TEMP\\[^\\]+\\RESOURCES\\APP\\SERVICEHUB\\$", @"\Temp\*\resources\app\ServiceHub\", Util.RX);
            k = Regex.Replace(k, @"\\IS-[A-Z0-9]+\.TMP\\$", @"\IS-*.TMP\", Util.RX);
            k = Regex.Replace(k, @"\\\{[0-9A-F-]{36}\}\\\.(BE|CR)\\$", @"\{*}\.$1\", Util.RX);
            return k;
        }

        /// <summary>true = show; noise is counted, trusted dropped (LOLBins and flagged paths are always shown).</summary>
        bool Keep(string p)
        {
            if (Rules.Flags(p).Count > 0) return true;
            int h = Hot(p);
            if (h == 1) { var k = NoiseKey(p); qk[k] = qk.TryGetValue(k, out var n) ? n + 1 : 1; }
            return h == 2;
        }

        static DateTime? PcaTime(string s)
        {
            return DateTime.TryParseExact(s.Trim(), new[] { "yyyy-MM-dd HH:mm:ss.fff", "yyyy-MM-dd HH:mm:ss" }, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var t) ? t : (DateTime?)null;
        }

        /// <summary>PCA writes %USERPROFILE% etc. without saying which user, and other drives without the letter.</summary>
        string PcaPath(string p)
        {
            p = p.Trim();
            var m = Regex.Match(p, "^%(USERPROFILE|LOCALAPPDATA|APPDATA|TEMP|TMP)%(.*)$", Util.RX);
            if (m.Success)
            {
                string sub;
                switch (m.Groups[1].Value.ToUpperInvariant())
                {
                    case "LOCALAPPDATA": sub = @"\AppData\Local"; break;
                    case "APPDATA": sub = @"\AppData\Roaming"; break;
                    case "TEMP": case "TMP": sub = @"\AppData\Local\Temp"; break;
                    default: sub = ""; break;
                }
                var cand = c.Profiles.Select(x => x.Path + sub + m.Groups[2].Value).ToList();
                var hit = cand.FirstOrDefault(x => File.Exists(x) || Directory.Exists(x));
                if (hit != null) return hit;
                if (cand.Count == 1) return cand[0];
                return p;
            }
            if (p.StartsWith("%")) return Environment.ExpandEnvironmentVariables(p);
            if (Regex.IsMatch(p, @"^\\[^\\]"))
            {
                foreach (var d in DriveInfo.GetDrives()) { var x = d.Name.TrimEnd('\\') + p; if (File.Exists(x)) return x; }
                // the file is gone: the one drive that still has its folder (a game uninstalled from D:\Games\X)
                var folder = Path.GetDirectoryName(p);
                var withFolder = folder != null && folder.Length > 1
                    ? DriveInfo.GetDrives().Select(d => d.Name.TrimEnd('\\') + p).Where(x => { try { return Directory.Exists(Path.GetDirectoryName(x)); } catch { return false; } }).ToList()
                    : new List<string>();
                if (withFolder.Count == 1) return withFolder[0];
                return "?:" + p;
            }
            return p;
        }

        static string Rot13(string s)
        {
            var a = s.ToCharArray();
            for (int i = 0; i < a.Length; i++)
            {
                char ch = a[i];
                if (ch >= 'A' && ch <= 'Z') a[i] = (char)('A' + (ch - 'A' + 13) % 26);
                else if (ch >= 'a' && ch <= 'z') a[i] = (char)('a' + (ch - 'a' + 13) % 26);
            }
            return new string(a);
        }

        string UaPath(string n, string profile)
        {
            var m = Regex.Match(n, @"^(\{[0-9A-F-]{36}\})(.*)$", Util.RX);
            if (m.Success)
            {
                var b = KnownFolder(m.Groups[1].Value.ToUpperInvariant(), profile);
                return b == null ? null : b + m.Groups[2].Value;
            }
            return Regex.IsMatch(n, @"^[a-z]:\\", Util.RX) ? n : null;
        }

        /// <summary>Known folder GUIDs used by UserAssist.</summary>
        string KnownFolder(string g, string pr)
        {
            switch (g)
            {
                case "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}": return c.WinDir + @"\System32";
                case "{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}": return c.WinDir + @"\SysWOW64";
                case "{F38BF404-1D43-42F2-9305-67DE0B28FC23}": return c.WinDir;
                case "{6D809377-6AF0-444B-8957-A3773F02200E}": return Ctx.Env("ProgramW6432");
                case "{905E63B6-C1BF-494E-B29C-65B732D3D21A}": return Ctx.Env("ProgramFiles");
                case "{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}": return Ctx.Env("ProgramFiles(x86)");
                case "{6365D5A7-0F0D-45E5-87F6-0DA56B6A4F7D}": return Ctx.Env("CommonProgramW6432");
                case "{DE974D24-D9C6-4D3E-BF91-F4455120B917}": return Ctx.Env("CommonProgramFiles(x86)");
                case "{62AB5D82-FDC1-4DC3-A9DD-070D1D495D97}": return Ctx.Env("ProgramData");
                case "{0762D272-C50A-4BB0-A382-697DCD729B80}": return c.SystemDrive + @"\Users";
                case "{5E6C858F-0E22-4760-9AFE-EA3317B67173}": return pr;
                case "{374DE290-123F-4565-9164-39C4925E467B}": return pr + @"\Downloads";
                case "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}": return pr + @"\Desktop";
                case "{FDD39AD0-238F-46AF-ADB4-6C85480369C7}": return pr + @"\Documents";
                case "{F1B32785-6FBA-4FCF-9D55-7B8E7F157091}": return pr + @"\AppData\Local";
                case "{3EB685DB-65F9-4CF6-A03A-E3EF65729F3D}": return pr + @"\AppData\Roaming";
                default: return null;
            }
        }

        class ShimEntry { public int N; public string P; public DateTime? M; }

        /// <summary>Windows 10/11 format: header (0x30 or 0x34 bytes), then '10ts' entries.</summary>
        static List<ShimEntry> Shim(byte[] b)
        {
            var o = new List<ShimEntry>();
            if (b == null || b.Length < 0x34) return o;
            int i = BitConverter.ToInt32(b, 0);
            if (i != 0x30 && i != 0x34) throw new Exception($"unsupported format (header 0x{i:X})");
            int n = 0;
            while (i + 14 <= b.Length)
            {
                if (Encoding.ASCII.GetString(b, i, 4) != "10ts") break;
                int len = BitConverter.ToInt32(b, i + 8); int pl = BitConverter.ToUInt16(b, i + 12);
                if (i + 14 + pl + 8 > b.Length) break;
                o.Add(new ShimEntry { N = n, P = Encoding.Unicode.GetString(b, i + 14, pl), M = Util.FtTime(BitConverter.ToInt64(b, i + 14 + pl)) });
                i += 12 + len; n++;
            }
            return o;
        }
    }
}
