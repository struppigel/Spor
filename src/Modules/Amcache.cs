using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace Spor.Modules
{
    /// <summary>
    /// Amcache.hve: Root\InventoryApplicationFile and Root\InventoryDriverBinary. The time shown is the last write of the entry's
    /// key (UTC), NOT an execution time: Windows also rewrites entries in inventory scans. Entries written at most 5 s apart form
    /// a run: runs of Batch+ entries are inventory scans (collapsed with folder counts), runs with Burst+ shown entries are
    /// install/update bursts (collapsed with names). Flagged entries are always listed.
    /// The hive is locked, so it is copied first (plain copy, else esentutl /y /vss, which some AVs alert on); the copy is deleted.
    /// </summary>
    class Amcache : IModule
    {
        public string Id => "amcache";
        public string Name => "AMCACHE";
        public string Description => "files and drivers Windows recorded";

        const string NoiseList = @"^\\(\$WINREAGENT|\$WINDOWS\.~BT|\$WINDOWS\.~WS)\\|\\PACKAGE CACHE\\|\\APPDATA\\LOCAL\\PROGRAMS\\MICROSOFT VS CODE\\|\\APPDATA\\LOCAL\\MICROSOFT\\(EDGE|ONEDRIVE)\\|\\PYTHON\d+\\(LIB|DLLS)\\";
        static readonly Regex Exe = new Regex(@"\.(exe|scr|com)$", Util.RX);
        static readonly Regex Sys = new Regex(@"^[a-z]:\\windows\\(system32|syswow64)\\([^\\]+)$", Util.RX);
        static readonly Regex Pf = new Regex(@"^[a-z]:\\program files( \(x86\))?\\", Util.RX);
        static readonly Regex DrvFolder = new Regex(@"^[a-z]:\\windows\\(system32|syswow64)\\(drivers|driverstore)\\", Util.RX);
        static readonly Regex OrigName = new Regex(@"^[^\\/:*?""<>|,@]+\.(exe|dll|com|scr|cpl|sys)$", Util.RX);

        Ctx c;
        Regex noise;

        class Entry
        {
            public string Key; public DateTime Time;
            public Dictionary<string, object> V = new Dictionary<string, object>(Util.IC);
            public string S(string n) => V.TryGetValue(n, out var o) ? (Convert.ToString(o) ?? "").Trim() : "";
            public object G(string n) => V.TryGetValue(n, out var o) ? o : null;
        }

        class Row
        {
            public DateTime T; public string P, I, K, Ls, Lb, Sha, D; public List<string> F; public int R;   // I = display, K = note, D = description
        }

        class Batches
        {
            public Dictionary<Entry, int> Map = new Dictionary<Entry, int>();   // entry -> run number (1-based), only runs of Burst+ entries
            public List<List<Entry>> Runs = new List<List<Entry>>();
            public int Run(Entry e) => Map.TryGetValue(e, out var r) ? r : 0;
        }

        public void Execute(Ctx ctx)
        {
            c = ctx; noise = Rules.Noise(NoiseList);
            var src = Path.Combine(c.WinDir, @"appcompat\Programs\Amcache.hve");
            if (!File.Exists(src)) { c.Out.None("Amcache.hve not found: " + src); return; }
            var dir = Path.Combine(c.Temp, "amcache");
            Directory.CreateDirectory(dir);
            var hive = Path.Combine(dir, "Amcache.hve");
            string how = null;
            foreach (var x in new[] { "", ".LOG1", ".LOG2" })   // the logs let Windows replay changes that are not yet in the hive file
            {
                if (!File.Exists(src + x)) continue;
                try { var h = c.CopyLocked(src + x, hive + x); if (x == "") how = h; } catch { }
            }
            if (!File.Exists(hive)) { c.Out.None("could not copy Amcache.hve (locked, and the shadow copy and esentutl /vss failed)"); return; }
            List<Entry> files, drv;
            try
            {
                using (var root = Native.LoadHive(hive))
                {
                    files = ReadKey(root, @"Root\InventoryApplicationFile");
                    drv = ReadKey(root, @"Root\InventoryDriverBinary");
                }
            }
            catch (Exception e) { c.Out.None("could not load the Amcache copy: " + e.Message); return; }
            Report(files, drv, how);
        }

        static List<Entry> ReadKey(RegistryKey root, string path)
        {
            var list = new List<Entry>();
            using (var k = root.OpenSubKey(path))
            {
                if (k == null) return list;
                foreach (var n in k.GetSubKeyNames())
                    using (var s = k.OpenSubKey(n))
                    {
                        if (s == null) continue;
                        var e = new Entry { Key = n, Time = Native.LastWrite(s) ?? DateTime.MinValue };
                        foreach (var v in s.GetValueNames()) e.V[v] = s.GetValue(v);
                        list.Add(e);
                    }
            }
            return list;
        }

        static string Sha(object v) { var s = (Convert.ToString(v) ?? "").Trim(); return s.Length == 44 && s.StartsWith("0000") ? s.Substring(4) : s; }
        static string Short(string s, int n) => s;
        /// <summary>File name; entries without a Name value only have the key name, which Windows cuts to 16 characters (shown with …).</summary>
        static string Nm(Entry e) { var n = e.S("Name"); if (n.Length > 0) return n; n = e.Key.Split('|')[0]; return n.Length >= 16 ? n + "…" : n; }

        /// <summary>What else an entry says about the file: product, publisher, version, Store package.</summary>
        static string Describe(Entry e)
        {
            var ver = new[] { "Version", "BinProductVersion", "ProductVersion" }.Select(e.S).FirstOrDefault(x => x.Length > 0);
            var appx = e.S("AppxPackageFullName"); if (appx.Length > 0) appx = "Store app " + appx.Split('_')[0];
            var parts = new[] { e.S("ProductName"), e.S("Publisher"), ver, appx }.Where(x => !string.IsNullOrEmpty(x)).Select(x => Short(x, 50)).Distinct(Util.IC);
            return string.Join(", ", parts);
        }
        static string Pth(Entry e) => e.S("LowerCaseLongPath").Replace('/', '\\');
        static string Top(string p) { var s = p.Split('\\'); return string.Join("\\", s.Take(Math.Min(6, s.Length - 2) + 1)); }

        Batches Batch(List<Entry> list)
        {
            var b = new Batches(); List<Entry> cur = new List<Entry>();
            foreach (var e in list.Where(e => e.Time >= c.Since).OrderBy(e => e.Time))
            {
                if (cur.Count > 0 && (e.Time - cur[cur.Count - 1].Time).TotalSeconds > 5) { b.Runs.Add(cur); cur = new List<Entry>(); }
                cur.Add(e);
            }
            if (cur.Count > 0) b.Runs.Add(cur);
            for (int i = 0; i < b.Runs.Count; i++)
                if (b.Runs[i].Count >= c.Opt.Burst) foreach (var e in b.Runs[i]) b.Map[e] = i + 1;
            return b;
        }

        /// <summary>2 = show, 1 = known noise (counted), 0 = trusted (ignored)</summary>
        int Hot(string p, bool check = false)
        {
            var m = Rules.DrivePath.Match(p);
            if (!m.Success) return 2;
            var d = m.Groups[1].Value; var rel = m.Groups[2].Value;
            if (Rules.OddChars(rel) || Rules.Dbl.IsMatch(rel) || Rules.Disg.IsMatch(rel)) return 2;
            if (!Rules.Whitelist) return 2;
            if (!d.Equals(c.SystemDrive, StringComparison.OrdinalIgnoreCase) || Rules.Risky.IsMatch(rel)) return 2;
            bool unsignedExe = check && Exe.IsMatch(p) && !c.SignedOk(p);   // only executables: Amcache also lists thousands of DLLs
            if (noise.IsMatch(rel)) return Signature.Applies(p) && !c.SignedOk(p) ? 2 : 1;   // every signable file: injected DLLs live in app folders
            if (Rules.Trusted.IsMatch(rel)) return unsignedExe ? 2 : 0;
            return 2;
        }

        string Key(string p)
        {
            string d = "", rel = p;
            var m = Rules.DrivePath.Match(p);
            if (m.Success) { d = m.Groups[1].Value; rel = m.Groups[2].Value; }
            var n = noise.Match(rel);
            var k = d + (n.Success ? rel.Substring(0, n.Index + n.Length) : rel);
            return Rules.SxsVersion.Replace(Rules.Fix(c.RealCase(k.TrimEnd('\\')) + (k.EndsWith("\\") ? "\\" : "")), "");
        }

        void Report(List<Entry> files, List<Entry> drv, string how)
        {
            var o = c.Opt;
            var fb = Batch(files); var db = Batch(drv);
            var bySha = new Dictionary<string, string>(Util.IC);
            var win = new Dictionary<string, List<DateTime>>(Util.IC);
            int nopath = 0;
            foreach (var e in files)
            {
                var p = Pth(e); if (p.Length == 0) { nopath++; continue; }
                var h = Sha(e.G("FileId")); if (h.Length > 0) bySha[h] = p;
                var m = Sys.Match(p);
                if (m.Success) { if (!win.TryGetValue(m.Groups[2].Value, out var l)) win[m.Groups[2].Value] = l = new List<DateTime>(); l.Add(e.Time); }
            }
            // System32 and SysWOW64 copy rewritten within 2 minutes = Windows servicing, not a run
            bool Serviced(string p, DateTime t)
            {
                var m = Sys.Match(p);
                if (!m.Success || !win.TryGetValue(m.Groups[2].Value, out var l)) return false;
                return l.Any(x => x != t && Math.Abs((x - t).TotalSeconds) <= 120);
            }
            bool IsScan(int run) => run > 0 && fb.Runs[run - 1].Count >= o.Batch;

            var qk = new Dictionary<string, int>(Util.IC);
            var rc = new Dictionary<int, int>();
            var rows = new List<Row>();
            foreach (var e in files)
            {
                if (e.Time < c.Since) continue;
                var n = Nm(e); var p = Pth(e); var sha = Sha(e.G("FileId")); int run = fb.Run(e);
                string via = null;
                if (p.Length == 0 && sha.Length > 0 && bySha.TryGetValue(sha, out var sp)) { p = sp; via = "path from an entry with the same SHA1"; }
                var fl = Rules.Flags(p, n);
                if (Rules.Whitelist && fl.Contains("!lolbin") && (IsScan(run) || (p.Length > 0 && (Pf.IsMatch(p) || Serviced(p, e.Time)))))
                    fl.Remove("!lolbin");
                // no path (name = key name, cut to 16 chars by Windows): show only files not belonging to an installed program (ProgramId ...ffff)
                int h = p.Length > 0 ? Hot(p, !IsScan(run)) : (!Rules.Whitelist || e.S("ProgramId").EndsWith("ffff", StringComparison.OrdinalIgnoreCase) ? 2 : 0);
                if (fl.Count == 0)
                {
                    if (h == 1) { var k = Key(p); qk[k] = qk.TryGetValue(k, out var x) ? x + 1 : 1; continue; }
                    if (h == 0) continue;
                    if (run > 0) rc[run] = rc.TryGetValue(run, out var x2) ? x2 + 1 : 1;   // candidate for collapsing
                }
                var on = e.S("OriginalFileName"); string orig = null;
                if (OrigName.IsMatch(on) && !Regex.Replace(on, @"\.[^.]*$", "").Equals(Regex.Replace(n, @"\.[^.]*$", ""), StringComparison.OrdinalIgnoreCase))
                {
                    orig = "original name " + on;
                    if (Rules.Lol.IsMatch("\\" + on)) fl.Add("!renamed-lolbin");
                }
                var disp = p.Length > 0 ? Rules.Fix(c.RealCase(p)) : n;
                if (sha.Length > 0 && p.Length > 0) c.AmSha1[disp] = sha;
                rows.Add(new Row { T = e.Time, P = p, I = disp, Sha = sha, D = p.Length > 0 ? null : Describe(e), F = fl, K = string.Join(", ", new[] { orig, via }.Where(x => x != null)), R = run > 0 && fl.Count == 0 ? run : 0, Ls = p.Length > 0 ? Top(p) : "(no path)", Lb = p.Length > 0 ? Util.Leaf(p) : n });
            }
            // scans: run of Batch+ entries in total (hidden); bursts: Burst+ shown entries in one run (one line with the names)
            var hid = new Dictionary<int, List<string>>();
            var nop = new List<Row>();
            foreach (var x in rows)
            {
                if (x.R > 0 && (IsScan(x.R) || (rc.TryGetValue(x.R, out var n) && n >= o.Burst)))
                {
                    if (!hid.TryGetValue(x.R, out var l)) hid[x.R] = l = new List<string>();
                    l.Add(x.P.Length > 0 ? Rules.Fix(c.RealCase(x.P)) : x.I);   // full path (or the name Windows kept): needed for removal
                    continue;
                }
                var flags = x.F.Where(f => f != "!lolbin").ToList();   // the timeline adds !lolbin itself where it applies
                if (x.P.Length > 0) c.Event(x.T, "AM", x.P, x.K.Length > 0 ? x.K : null, flags);
                else nop.Add(x);
            }
            var scans = new List<(DateTime T, int N, string Top, List<string> Files)>();
            // per folder: "folder\ => a.exe, b.dll" (entries without path: "(no path) => names"), cut into pieces that fit on a sub-line,
            // each with its folder (a reader takes the folder from every line)
            List<(string Folder, List<string> Names)> Groups(List<string> l) => l.Distinct(Util.IC).GroupBy(x => x.Contains("\\") ? Util.Folder(x) + "\\" : "(no path)", Util.IC)
                .OrderByDescending(g => g.Count()).Select(g => (g.Key, g.Select(x => x.Contains("\\") ? Util.Leaf(x) : x).ToList())).ToList();
            List<string> PerFolder(List<string> l) =>
                Groups(l).SelectMany(g => Log.Chunks(g.Names, Math.Max(60, Log.ListWidth - g.Folder.Length - 4)).Select(p => g.Folder + " => " + p)).ToList();
            foreach (var kv in hid)
            {
                var r = fb.Runs[kv.Key - 1]; var l = kv.Value;
                if (r.Count >= o.Batch)
                    scans.Add((r[0].Time, l.Count, string.Join(", ", l.GroupBy(x => x.Contains("\\") ? Top(x) : "(no path)", Util.IC).OrderByDescending(g => g.Count()).Take(3).Select(g => g.Key + " (" + g.Count() + ")")), PerFolder(l)));
                else
                {
                    foreach (var g in Groups(l))   // one timeline line per folder, every file name on its files: sub-lines
                        c.Event(r[r.Count - 1].Time, "AM", null, text: $"install/update: {g.Folder} => {g.Names.Count} files",
                                more: Log.Chunks(g.Names).Select(p => ("files", p)).ToList());
                }
            }

            var odd = new List<(DateTime T, string P, List<string> F, string I)>();
            foreach (var e in drv)
            {
                bool inbox = Convert.ToInt32(e.G("DriverInBox") ?? 0) == 1;
                if (inbox && Rules.Whitelist) continue;
                var p = Regex.Replace(e.Key.Replace('/', '\\'), @"^\\\?\?\\", "");
                // signed or not: the file's real signature if it is still there (the company name is just metadata anyone can write)
                var sg = e.G("DriverSigned");
                bool uns = File.Exists(p) ? !c.SignedOk(p) : sg != null && Convert.ToInt32(sg) != 1;
                bool outside = !DrvFolder.IsMatch(p);
                int dr = db.Run(e);
                bool dscan = dr > 0 && db.Runs[dr - 1].Count >= o.Batch;
                var fl = new List<string>();
                if (uns) fl.Add("!unsigned");
                if (outside) fl.Add("!outside-driver-folders");
                var info = $"{Short(e.S("DriverCompany"), 40)}, {Short(e.S("Product"), 40)} {Short(e.S("DriverVersion"), 20)}".Trim(' ', ',');
                var sha = Sha(e.G("DriverId"));
                if (sha.Length > 0) c.AmSha1[Rules.Fix(c.RealCase(p))] = sha;
                if (!dscan) c.Event(e.Time, "DRV", p, info, fl);
                if (fl.Count > 0) odd.Add((e.Time, p, fl, info));
            }

            c.Out.Comment($"Read via {how}: {files.Count} file entries ({nopath} without path), {drv.Count} driver entries.");
            c.Out.Comment("Entries outside trusted locations written in the last " + o.Days + " days are in the timeline (AM, DRV). Written does not mean run:");
            c.Out.Comment("Windows also records files in inventory scans and when programs are installed or updated.");
            c.Out.Sub("Drivers that are unsigned or outside the driver folders (any time)");
            var dt = new Table("@time", "!status", "<flags", "*driver", "=details");
            foreach (var x in odd.OrderBy(x => x.T))
            {
                var f = c.F(x.P);
                dt.Add(Log.T(x.T), f.Status, Rules.FlagCol(x.F), f.Path, x.I);
                c.Find(x.T, f.Path + Rules.FlagText(x.F) + "  (driver)", "entry written");
            }
            dt.WriteTo(c.Out);
            c.Out.Sub("Entries without path (not in the timeline)",
                "Windows stores no path and often no name for these; the name is then cut to 16 characters (…). sha1 = the file when recorded.");
            var nt = new Table("@time", "<flags", "sha1", "*name", "=details");
            foreach (var x in nop.OrderBy(x => x.T))
            {
                nt.Add(Log.T(x.T), Rules.FlagCol(x.F), x.Sha.ToUpperInvariant(), Rules.Fix(x.I), string.Join(", ", new[] { x.D, x.K }.Where(v => !string.IsNullOrEmpty(v))));
                if (Rules.Strong(x.F).Count > 0) c.Find(x.T, Rules.Fix(x.I) + Rules.FlagText(x.F) + "  (Amcache entry without path)", "entry written");
            }
            nt.WriteTo(c.Out);
            c.Out.Sub("Inventory scans (not in the timeline)");
            var st = new Table("@time", "*entries", "mostly in");
            foreach (var x in scans.OrderBy(x => x.T)) { st.Add(Log.T(x.T), x.N + " entries", x.Top); foreach (var fo in x.Files) st.More("files", fo); }
            st.WriteTo(c.Out);
            c.Out.Hidden(qk, "entries");
        }
    }
}
