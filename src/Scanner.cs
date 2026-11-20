using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using Spor.Modules;

namespace Spor
{
    interface IModule
    {
        string Id { get; }
        string Name { get; }          // section heading, e.g. "PREFETCH"
        string Description { get; }   // shown in the window and after the heading
        void Execute(Ctx c);
    }

    /// <summary>Runs the selected modules and writes the log. Used by the window and the command line.</summary>
    static class Scanner
    {
        public static readonly IModule[] All =
        {
            new Prefetch(), new Amcache(), new ExecEvidence(), new Files(), new Timestomp(), new Downloads(), new Software(), new Persistence(),
            new Processes(), new Security(), new ClickFix(), new RemoteAccess(), new Network(), new Accounts()
        };

        /// <summary>Timeline source tags, in the order they are listed on a line.</summary>
        static readonly (string Tag, string Meaning)[] Tags =
        {
            ("PF", "Prefetch: program run"),
            ("PCA", "Program Compatibility Assistant: program launched"),
            ("UA", "UserAssist: program started from Explorer/Start menu"),
            ("BAM", "Background Activity Moderator: program ran"),
            ("4688", "Security event 4688: process created (only with process creation auditing)"),
            ("SYSMON", "Sysmon event 1: process created"),
            ("PROC", "process running now (time = when it started)"),
            ("MPL", "Defender looked the file up in the cloud (usually when it ran or was written)"),
            ("SRU", "SRUM: program first active in the window"),
            ("AM", "Amcache: time = when Windows wrote the entry (the file was there; not necessarily run)"),
            ("SC", "ShimCache: time = the file's modification time (not when it ran or arrived: a copied file keeps its old time)"),
            ("NEW", "file created"),
            ("STP", "timestamps set, possibly faked (timestomping)"),
            ("DL", "browser download"),
            ("OPN", "file opened in Explorer"),
            ("ISO", "disk image mounted"),
            ("ARC", "archive tool used"),
            ("INS", "software installed, updated or removed"),
            ("AUT", "Run key changed"),
            ("SVC", "service installed or changed"),
            ("TSK", "scheduled task created, changed or deleted"),
            ("STA", "Startup folder item created"),
            ("DRV", "Amcache: driver recorded"),
            ("DEF", "Defender event"),
            ("LOG", "event log cleared"),
            ("USR", "account created or changed"),
            ("CAM", "webcam used (last use per program)"),
            ("MIC", "microphone used (last use per program)"),
            ("RUN", "Run dialog (Win+R) used"),
            ("ADR", "Explorer address bar"),
            ("PSH", "PowerShell history written"),
            ("RMM", "remote access tool"),
        };

        /// <summary>"EXECUTION EVIDENCE" -> "Execution evidence", "CLICKFIX" -> "ClickFix".</summary>
        public static string Pretty(IModule m) => m.Id == "clickfix" ? "ClickFix" : m.Name.Substring(0, 1) + m.Name.Substring(1).ToLowerInvariant();

        public static string Version
        {
            get { var v = Assembly.GetExecutingAssembly().GetName().Version; return $"{v.Major}.{v.Minor}.{v.Build}"; }
        }

        public static string DefaultLog() =>
            Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) ?? ".", "Spor.txt");

        /// <summary>Returns the log path. progress(text, done, total) is called before each module and at the end.</summary>
        public static string Run(Options o, Action<string, int, int> progress)
        {
            Rules.Whitelist = o.Whitelist;
            Signature.Reset();   // a new scan in the same window must not reuse old results
            Rules.ExtraNoise = o.ExtraNoise ?? "";
            var mods = All.Where(m => o.Modules == null || o.Modules.Contains(m.Id)).ToList();
            var total = Stopwatch.StartNew();
            var sections = new List<Log>();
            var times = new List<string>();
            var log = new Log();
            using (var c = new Ctx(o))
            {
                var startErr = c.Err.ToList(); c.Err.Clear();
                for (int i = 0; i < mods.Count; i++)
                {
                    var m = mods[i];
                    progress?.Invoke(m.Description, i, mods.Count);
                    c.Out = new Log(); c.Module = Pretty(m); c.Err.Clear();
                    var sw = Stopwatch.StartNew();
                    c.Out.Heading(m.Name + " - " + m.Description);
                    try { m.Execute(c); }
                    catch (Exception e) { c.Err.Add($"MODULE FAILED: {e.GetType().Name}: {e.Message} at {e.StackTrace?.Split('\n').FirstOrDefault()?.Trim()}"); }
                    if (c.Err.Count > 0) { c.Out.Sub("Errors"); var et = new Table("*error"); foreach (var e in c.Err) et.Add(e); et.WriteTo(c.Out); }
                    sections.Add(c.Out);
                    times.Add($"{m.Id} {sw.Elapsed.TotalSeconds:N1} s");
                }
                progress?.Invoke("Writing the log", mods.Count, mods.Count);
                c.Err.Clear();
                Correlate.Run(c);   // checks across modules (script-runtime launchers); its errors go to the header
                startErr.AddRange(c.Err); c.Err.Clear();

                // known malware (curated patterns) over everything collected; before the timeline, so its file lines get !known-malware.
                // Signers of files first checked by the timeline: a second pass after it (SUMMARY findings only).
                var asw = Stopwatch.StartNew();
                c.Module = "Autodetect";
                try { Autodetect.Run(c); }
                catch (Exception e) { c.Err.Add($"Autodetect FAILED: {e.GetType().Name}: {e.Message}"); }
                asw.Stop();
                var timeline = Timeline(c, out var rows);
                asw.Start();
                try { Autodetect.Companies(c); }
                catch (Exception e) { c.Err.Add($"Autodetect FAILED: {e.GetType().Name}: {e.Message}"); }
                times.Add($"autodetect {asw.Elapsed.TotalSeconds:N1} s");
                startErr.AddRange(c.Err); c.Err.Clear();
                Header(c, log, startErr);
                Summary(c, log, rows);
                Append(log, timeline);
                foreach (var s in sections) Append(log, s);
                Files(c, log);
                Legend(log);
                log.W();
                if (c.ShadowNote != null) log.W(c.ShadowNote);
                log.Heading($"End of log. Scan took {total.Elapsed.TotalSeconds:N1} s ({string.Join(", ", times)})");
            }

            string path = o.Out ?? DefaultLog();
            try { Write(path, log); }
            catch when (o.Out == null)
            {
                path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "Spor.txt");
                Write(path, log);
            }
            return path;
        }

        static void Append(Log log, Log part)
        {
            if (log.Lines.Count > 0 && log.Lines[log.Lines.Count - 1].Length > 0) log.W();
            log.Lines.AddRange(part.Lines);
        }

        static void Write(string path, Log log) => File.WriteAllText(path, string.Join("\r\n", log.Lines) + "\r\n", new UTF8Encoding(true));

        static void Header(Ctx c, Log log, List<string> err)
        {
            var o = c.Opt;
            bool admin;
            using (var id = WindowsIdentity.GetCurrent()) admin = new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
            string os = "";
            try
            {
                using (var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion"))
                {
                    var build = Convert.ToString(k.GetValue("CurrentBuildNumber"));
                    var name = Convert.ToString(k.GetValue("ProductName"));
                    if (int.TryParse(build, out var b) && b >= 22000) name = name.Replace("Windows 10", "Windows 11");   // ProductName still says 10 on 11
                    os = $"{name} {k.GetValue("DisplayVersion")}, build {build}.{k.GetValue("UBR")}";
                }
            }
            catch { }
            var now = DateTime.Now;
            log.Heading($"Spor {Version} - forensic triage log");
            log.W($"Created:   {now.ToUniversalTime().ToString(Log.TimeFmt)} UTC (local time {now:HH:mm}, UTC{now:zzz})");
            log.W($"Computer:  {Environment.MachineName}, {os}, {(Environment.Is64BitProcess ? "64-bit" : "32-bit")}");
            log.W($"Run by:    {Environment.UserName}{(admin ? " (administrator)" : "  -- NOT AS ADMINISTRATOR: most results are missing --")}");
            if (Native.MachineSid() is string msid) log.W($"Machine SID: {msid}");
            log.W($"Users:     {string.Join(", ", c.Profiles.Select(p => p.User))}");
            log.W($"Options:   last {o.Days} days, whitelist {(Rules.Whitelist ? "on" : "OFF (everything shown)")}{(Rules.ExtraNoise.Length > 0 ? ", extra noise " + Rules.ExtraNoise : "")}, " +
                  (o.NoHash ? "no hashes" : o.Algo + " hashes of files up to " + o.MaxMB + " MB") +
                  (o.Modules != null ? ", only " + string.Join(", ", o.Modules) : "") +
                  (Autodetect.Patterns.Source != "built in" ? ", autodetect patterns from " + Autodetect.Patterns.Source : ""));
            log.W("Times:     UTC");
            log.W("Format:    one item per line: time [sources] item [status] => details <==== flags (parts left out when empty);");
            log.W("           (lines in brackets) are comments, \"(line: ...)\" names the parts; indented \"key: value\" lines belong to the item above.");
            log.W("           Hashes, signatures and versions of the files: FILES near the end. Sources, status words and flags: LEGEND at the end.");
            foreach (var e in err) log.W("Error:     " + e);
        }

        class Row { public DateTime T; public string Src, Status, Obj, Details; public List<string> Flags; public List<string> Paths = new List<string>(); public List<(string Key, string Value)> More; }

        /// <summary>Path with version numbers, dated / numbered / GUID folder names replaced by #, for grouping.</summary>
        static string Shape(string p)
        {
            int k = p.LastIndexOf('\\');
            if (k < 0) return p;
            // a folder name with a GUID or a long number (date, time, id) becomes "#" as a whole (20261103-075951-1, {GUID}, ...);
            // in other folder names only version numbers do (app-1.0.9267 -> app-#, Claude_5.1.2.0_x64__id -> Claude_#_x64__id)
            var segs = p.Substring(0, k).Split('\\').Select(seg =>
                Regex.IsMatch(seg, @"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|\d{6,}", RegexOptions.IgnoreCase) ? "#"
                : Regex.Replace(seg, @"\d+([._]\d+)+", "#"));
            return string.Join("\\", segs) + p.Substring(k);
        }

        /// <summary>
        /// For lines whose sources only record a file, not an action: what the line's time is. Lines with a run, download, ... need none.
        /// </summary>
        static string TimeMeaning(IEnumerable<string> sources)
        {
            var s = sources.Distinct().ToList();
            if (s.All(x => x == "SC")) return "file modified at this time (ShimCache: no proof it ran; a copied file keeps its old time)";
            if (s.All(x => x == "AM")) return "Amcache entry written at this time (no proof it ran)";
            if (s.All(x => x == "SC" || x == "AM")) return "file modified or Amcache entry written at this time (no proof it ran)";
            return null;
        }

        static Log Timeline(Ctx c, out List<Row> result)
        {
            var rows = new List<Row>();
            var signedHidden = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            int defUpdates = 0;
            int Order(string t) { for (int i = 0; i < Tags.Length; i++) if (Tags[i].Tag == t) return i; return 99; }
            // whitelist: a file validly signed by a well-known publisher, without flags, is counted instead of listed
            // (a deleted file: its signed newer version next to it, see Ctx.Replacement)
            string SignedBy(string path)
            {
                if (!Rules.Whitelist || !Signature.Applies(path) || Rules.Strong(Rules.Flags(path)).Count > 0 || Rules.Lol.IsMatch(path)
                    || Rules.Interpreter.IsMatch(path) || Rules.DropLocation(path) || c.RuntimeLaunchers.Contains(c.RealCase(path))) return null;
                var real = c.RealCase(path);
                if (!File.Exists(real)) real = c.Replacement(real);
                if (real == null) return null;
                var sg = Signature.Check(real);
                var who = (sg.Signer ?? "").Replace(" (catalog)", "").Replace(" (package)", "");
                return sg.Valid && Rules.TrustedSigners.Contains(who) ? who : null;
            }
            // one group per file; files in folders that differ only in numbers (version folders, timestamped or random temp folders)
            // are one group too, so a test harness or an auto-updater does not fill the timeline
            foreach (var g in c.Events.Where(e => e.Path != null).GroupBy(e => Shape(e.Path), Util.IC))
            {
                // same file within 2 minutes = one line (one program start, seen by several sources)
                var cl = new List<List<TEvent>>();
                foreach (var e in g.OrderBy(e => e.T))
                {
                    if (cl.Count == 0 || (e.T - cl[cl.Count - 1].Last().T).TotalSeconds > 120) cl.Add(new List<TEvent>());
                    cl[cl.Count - 1].Add(e);
                }
                // !known-malware is on every event of the file: it does not keep repeats (first and last time are enough)
                bool Strong(List<TEvent> x) => x.Any(e => Rules.Strong(Rules.Flags(e.Path)).Count > 0 || (e.Flags != null && Rules.Strong(e.Flags).Any(f => f != Autodetect.Flag)));
                var paths = g.Select(e => e.Path).Distinct(Util.IC).ToList();
                // the same file again and again (python.exe, an updater): keep the first and the last time in the window,
                // and every flagged one; the last line says how many are left out
                int dropped = 0;
                if (cl.Count > 2)
                {
                    var keep = cl.Where((x, i) => i == 0 || i == cl.Count - 1 || Strong(x)).ToList();
                    dropped = cl.Count - keep.Count;
                    cl = keep;
                }
                var first = cl[0].Min(e => e.T);
                if (!cl.Any(x => x.Any(e => e.Flags != null && e.Flags.Count > 0)))
                {
                    if (Rules.Whitelist && paths.All(Rules.DefenderUpdate) && paths.All(p => Rules.Flags(p).Count == 0)) { defUpdates += cl.Count + dropped; continue; }
                    var who = paths.Select(SignedBy).ToList();
                    if (who.All(w => w != null)) { var k = who[0]; signedHidden[k] = (signedHidden.TryGetValue(k, out var n) ? n : 0) + cl.Count + dropped; continue; }
                }
                foreach (var x in cl)
                {
                    var path = x.OrderByDescending(e => e.T).First().Path;
                    var ex = x.Where(e => !string.IsNullOrEmpty(e.Extra)).Select(e => e.Extra).Distinct().ToList();
                    ex.InsertRange(0, x.Where(e => e.Known != null).Select(e => e.Known).Distinct());   // the family first
                    if (TimeMeaning(x.Select(e => e.Src)) is string tm) ex.Add(tm);   // last, so the other details keep their place
                    bool last = x == cl[cl.Count - 1];
                    if (dropped > 0 && last)
                        ex.Add($"+{dropped} more times since {first:yyyy-MM-dd HH:mm}" + (paths.Count > 1 ? $" in {paths.Count} folders that differ only in numbers, all listed below" : ""));
                    var f = c.F(path, !x.All(e => e.NoHash));
                    var row = new Row
                    {
                        T = x.Max(e => e.T), Src = string.Join(" ", x.Select(e => e.Src).Distinct().OrderBy(Order)), Status = f.Status, Obj = f.Path,
                        Details = string.Join("; ", ex), Flags = Rules.Flags(path).Concat(x.Where(e => e.Flags != null).SelectMany(e => e.Flags)).Distinct().ToList(),
                        // sub-lines of file events too (script files of a runtime launcher, ...)
                        More = x.Where(e => e.More != null).SelectMany(e => e.More).Distinct().ToList(),
                    };
                    if (row.More.Count == 0) row.More = null;
                    // grouped lines: every real path with its own times, so nothing has to be guessed for removal
                    if (paths.Count > 1 && last)
                        foreach (var pg in g.GroupBy(e => e.Path, Util.IC).OrderBy(pg => pg.Max(e => e.T)))
                        {
                            var pf = c.F(pg.Key, !pg.All(e => e.NoHash));
                            var times = pg.Select(e => e.T).Distinct().Count();
                            row.Paths.Add(Log.Item(pf.Path, pf.Status, $"{Log.T(pg.Max(e => e.T))}" + (times > 1 ? $", first {Log.T(pg.Min(e => e.T))}, {times} times" : ""),
                                                   Rules.FlagCol(Rules.Flags(pg.Key))));
                        }
                    rows.Add(row);
                }
            }
            foreach (var e in c.Events.Where(e => e.Path == null))
                rows.Add(new Row { T = e.T, Src = e.Src, Status = "-", Obj = e.Text, Flags = e.Flags ?? new List<string>(), More = e.More,
                                   Details = string.Join("; ", new[] { e.Extra, TimeMeaning(new[] { e.Src }) }.Where(s => !string.IsNullOrEmpty(s))) });
            rows = rows.OrderBy(x => x.T).ToList();   // oldest first: read it like a story

            var log = new Log();
            log.Heading($"TIMELINE - last {c.Opt.Days} days, oldest first");
            log.Comment("Sources [PF AM ...], status [gone ...] and flags <==== !...: see LEGEND at the end of the log.");
            log.Comment("A file seen by several sources within 2 minutes is one line. A file seen many times: the first and the last time.");
            var hiddenParts = new List<string>();
            if (defUpdates > 0) hiddenParts.Add($"{defUpdates} runs of Defender update packages (AM_Delta_Patch_*.exe)");
            if (signedHidden.Count > 0)
                hiddenParts.Add($"{signedHidden.Values.Sum()} runs of files validly signed by well-known publishers, without flags: " +
                                string.Join(", ", signedHidden.OrderByDescending(kv => kv.Value).Select(kv => $"{kv.Key} {kv.Value}")));
            if (hiddenParts.Count > 0) log.Comment("Hidden (-nowhitelist lists them): " + string.Join("; ", hiddenParts) + ".");
            var t = new Table("@time", "[sources", "*file or event", "!status", "=details", "<flags");
            foreach (var r in rows) { t.Add(Log.T(r.T), r.Src, r.Obj, r.Status, r.Details, Rules.FlagCol(r.Flags)); foreach (var p in r.Paths) t.More("path", p); if (r.More != null) foreach (var m in r.More) t.More(m.Key, m.Value); }
            t.WriteTo(log);
            result = rows;
            return log;
        }

        static void Summary(Ctx c, Log log, List<Row> rows)
        {
            log.W();
            log.Heading("SUMMARY - flagged items; details in the sections below");
            log.Comment("time = when it happened, except: ShimCache = the file's modification time (a copied file keeps its old time), Amcache = when Windows wrote the entry,");
            log.Comment("Run keys and services = when the key was last changed, tasks and Startup items = file created, log and config files = file last written.");
            // hints (Rules.Hints) count only with a strong flag on the same line or in the same folder
            var strongFolders = new HashSet<string>(rows.Where(r => Rules.Strong(r.Flags).Count > 0 && Rules.DrivePath.IsMatch(r.Obj ?? ""))
                                                        .Select(r => Util.Folder(r.Obj)), Util.IC);
            List<string> Shown(Row r)
            {
                var strong = Rules.Strong(r.Flags);
                bool hints = strong.Count > 0 || (Rules.DrivePath.IsMatch(r.Obj ?? "") && strongFolders.Contains(Util.Folder(r.Obj)));
                return hints ? strong.Concat(Rules.HintsOf(r.Flags)).ToList() : strong;
            }
            var flagged = rows.Where(r => Shown(r).Count > 0).ToList();
            var lolbins = rows.Where(r => r.Flags.Contains("!lolbin") && Rules.DrivePath.IsMatch(r.Obj ?? "")).Select(r => Util.Leaf(r.Obj)).Distinct(Util.IC).ToList();
            var t = new Table("@time", "[from", "*item", "!status", "=details", "<flags");
            // sorted by time, oldest first; findings without a time (signatures, Run dialog, ...) at the end, in module order
            var items = flagged.Select(r => (T: (DateTime?)r.T, Fields: new[] { Log.T(r.T), "timeline " + r.Src, r.Obj, r.Status, r.Details, Rules.FlagCol(Shown(r)) }))
                .Concat(c.Findings.Distinct().Select(f => (T: f.T, Fields: new[] { Log.T(f.T), f.Module, f.Text, null, null, null })))
                .Select((x, i) => (x.T, x.Fields, I: i))
                .OrderBy(x => x.T.HasValue ? 0 : 1).ThenBy(x => x.T ?? DateTime.MaxValue).ThenBy(x => x.I);
            foreach (var x in items) t.Add(x.Fields);
            t.WriteTo(log, "nothing flagged");
            if (lolbins.Count > 0) log.Wrap("LOLBins run in the last " + c.Opt.Days + " days (normal on many PCs, see the timeline): ", lolbins);
        }

        static void Files(Ctx c, Log log)
        {
            var files = c.Sha256.Keys.Concat(c.Signer.Keys).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(k => k, StringComparer.OrdinalIgnoreCase).ToList();
            if (files.Count > 0)
            {
                log.W();
                log.Heading($"FILES - {c.Opt.Algo}, signature and version of the files as they are on disk now");
                log.Comment("One line per file. signature: valid / invalid / revoked / expired / unsigned, \"(catalog)\" = signed through a Windows catalog; thumbprint = certificate SHA1;");
                log.Comment("version: file version, description, product, company, original name; amcache sha1 = the file when Windows recorded it (differs if replaced since);");
                log.Comment("md5 = MD5 of the file now; size = bytes; created, modified = file times in LOCAL time of this PC (as FRST shows them), not UTC.");
                var t = new Table("*file", ">" + c.Opt.Algo.ToLowerInvariant(), "signature", "=version", "amcache sha1", "md5", "size", "created", "modified");
                foreach (var k in files)
                {
                    c.Sha256.TryGetValue(k, out var h); c.Signer.TryGetValue(k, out var sg); c.Version.TryGetValue(k, out var vi); c.AmSha1.TryGetValue(k, out var am);
                    c.Md5.TryGetValue(k, out var md5); bool meta = c.Meta.TryGetValue(k, out var fm);
                    t.Add(k, h ?? "not hashed", sg, vi == "none" ? null : vi, am?.ToUpperInvariant(), md5,
                          meta ? fm.Size.ToString() : null, meta ? Log.T(Util.FrstLocal(fm.Created, c.LocalOffset)) : null, meta ? Log.T(Util.FrstLocal(fm.Modified, c.LocalOffset)) : null);
                }
                t.WriteTo(log);
            }
            var amOnly = c.AmSha1.Where(kv => !c.Sha256.ContainsKey(kv.Key) && !c.Signer.ContainsKey(kv.Key)).ToList();
            if (amOnly.Count > 0)
            {
                log.W();
                log.Heading("AMCACHE FILES - SHA1 from Amcache of files not listed above (the file when Windows recorded it)");
                var t = new Table("*file", ">sha1");
                foreach (var kv in amOnly.OrderBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)) t.Add(kv.Key, kv.Value.ToUpperInvariant());
                t.WriteTo(log);
            }
        }

        /// <summary>Legend: one entry per line. Not item lines: parsers skip this section by its title.</summary>
        internal static void Legend(Log log)
        {
            log.W();
            log.Heading("LEGEND");
            log.W("Sources (timeline, in brackets after the time):");
            // at least two blanks after the longest code: parsers split code and meaning there
            int w = Tags.Max(t => t.Tag.Length) + 2;
            foreach (var t in Tags) log.W("    " + t.Tag.PadRight(w) + t.Meaning);
            log.W();
            log.W("Status (in brackets after a file; no status = the file is there and validly signed or not an executable):");
            foreach (var (k, v) in new[] {
                ("gone", "deleted since"), ("no access", "Spor could not read it"), ("unsigned", "executable without a signature"),
                ("invalid signature", "the signature does not verify (file changed after signing, untrusted root, ...); see FILES"),
                ("revoked signature", "the certificate was revoked or explicitly distrusted (e.g. stolen)"),
                ("expired signature", "the certificate expired and the signature has no timestamp"),
                ("volume not mounted", "the drive is not there now"), ("> N MB, not hashed", "too big for the hash limit") })
                log.W("    " + k.PadRight(20) + v);
            log.W();
            log.W("Flags (after <====):");
            foreach (var f in Rules.FlagLegend)
            {
                int i = f.IndexOf(" = ");
                log.W("    " + (i > 0 ? f.Substring(0, i).PadRight(28) + f.Substring(i + 3) : f));
            }
        }
    }
}
