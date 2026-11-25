using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
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
            new Processes(), new Security(), new ClickFix(), new RemoteAccess(), new Network(), new Accounts(), new Drops(), new Usb()
        };

        /// <summary>
        /// Scan profiles: which modules run. Default = everything except the USB drive listing; USB worm = the drive listing and the modules
        /// that show a worm's installed copy (persistence, processes, programs run, new files, Prefetch for runs from USB volumes); All = all.
        /// </summary>
        public static readonly (string Id, string Name, string[] Modules)[] Profiles =
        {
            ("default", "Default", All.Where(m => m.Id != "usb").Select(m => m.Id).ToArray()),
            ("usb", "USB worm", new[] { "prefetch", "exec", "files", "persistence", "processes", "usb" }),
            ("all", "All", All.Select(m => m.Id).ToArray()),
        };

        /// <summary>The modules of a profile (case-insensitive id); null for an unknown profile.</summary>
        public static HashSet<string> ProfileModules(string id)
        {
            var p = Profiles.FirstOrDefault(x => x.Id.Equals(id ?? "", StringComparison.OrdinalIgnoreCase));
            return p.Id == null ? null : new HashSet<string>(p.Modules, StringComparer.OrdinalIgnoreCase);
        }

        /// <summary>(pure) The modules a scan runs, in module order: the -modules list if given, else the profile's.</summary>
        internal static List<IModule> Selected(Options o)
        {
            var sel = o.Modules ?? ProfileModules(o.Profile) ?? ProfileModules("default");
            return All.Where(m => sel.Contains(m.Id)).ToList();
        }

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
            ("DRP", "drop folder sweep: a loader project folder in a Windows cache or system folder (time = folder created)"),
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
            ("USB", "USB storage device connected or disconnected"),
        };

        /// <summary>"EXECUTION EVIDENCE" -> "Execution evidence", "CLICKFIX" -> "ClickFix".</summary>
        public static string Pretty(IModule m) =>
            m.Id == "clickfix" ? "ClickFix" : m.Id == "usb" ? "USB drives" : m.Name.Substring(0, 1) + m.Name.Substring(1).ToLowerInvariant();

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
            Rules.Aggressive = o.Whitelist && o.Aggressive;
            Signature.Reset();   // a new scan in the same window must not reuse old results
            Rules.ExtraNoise = o.ExtraNoise ?? "";
            var mods = Selected(o);
            var total = Stopwatch.StartNew();
            var sections = new List<Log>();
            var times = new List<string>();
            var sigTimes = new List<string>();   // signature check time per module
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
                    var sig0 = Signature.CheckTime;
                    c.Out.Heading(m.Name + " - " + m.Description);
                    try { m.Execute(c); }
                    catch (Exception e) { c.Err.Add($"MODULE FAILED: {e.GetType().Name}: {e.Message} at {e.StackTrace?.Split('\n').FirstOrDefault()?.Trim()}"); }
                    if (c.Err.Count > 0) { c.Out.Sub("Errors"); var et = new Table("*error"); foreach (var e in c.Err) et.Add(e); et.WriteTo(c.Out); }
                    sections.Add(c.Out);
                    times.Add($"{m.Id} {sw.Elapsed.TotalSeconds:N1} s");
                    var sigs = (Signature.CheckTime - sig0).TotalSeconds;
                    if (sigs >= 0.5) sigTimes.Add($"{m.Id} {sigs:N1} s");
                }
                progress?.Invoke("Writing the log", mods.Count, mods.Count);
                c.Err.Clear();
                Correlate.Run(c);   // checks across modules (script-runtime launchers); its errors go to the header
                startErr.AddRange(c.Err); c.Err.Clear();
                c.ApplyMarks();     // flags modules gave a file (Defender detected it, ...) on all its timeline events

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
                // where the time goes: signature checks (counted in the module that checked a file first) and hashing (FILES)
                log.Heading($"End of log. Scan took {total.Elapsed.TotalSeconds:N1} s ({string.Join(", ", times)}); " +
                            $"{Signature.Checks} signature checks {Signature.CheckTime.TotalSeconds:N1} s ({string.Join(", ", sigTimes)}); " +
                            $"hashed {c.HashFiles} files, {c.HashBytes / 1024 / 1024} MB, {c.HashTime.TotalSeconds:N1} s");
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
            log.W($"Options:   last {o.Days} days, whitelist {(Rules.Aggressive ? "aggressive" : Rules.Whitelist ? "on" : "OFF (everything shown)")}{(Rules.ExtraNoise.Length > 0 ? ", extra noise " + Rules.ExtraNoise : "")}, " +
                  (o.NoHash ? "no hashes" : o.Algo + " hashes of files up to " + o.MaxMB + " MB") +
                  (o.Modules != null ? ", only " + string.Join(", ", Selected(o).Select(m => m.Id)) : ", profile " + (ProfileModules(o.Profile) != null ? o.Profile.ToLowerInvariant() : "default")) +
                  (Autodetect.Patterns.Source != "built in" ? ", autodetect patterns from " + Autodetect.Patterns.Source : "") +
                  (Rules.PublishersSource != null ? ", publishers from " + Rules.PublishersSource : "") +
                  (Whitelist.Source != null ? ", whitelist from " + Whitelist.Source : ""));
            log.W("Times:     UTC, except created and modified in FILES (local time of this PC, as FRST shows them)");
            log.W("Format:    one item per line: time [sources] item [status] => details <==== flags (parts left out when empty);");
            log.W("           (lines in brackets) are comments, \"(line: ...)\" names the parts; indented \"key: value\" lines belong to the item above.");
            log.W("           Hashes, signatures and versions of the files: FILES near the end. Sources, status words and flags: LEGEND at the end.");
            foreach (var e in err) log.W("Error:     " + e);
        }

        class Row { public DateTime T; public string Src, Status, Obj, Details, Aggr; public List<string> Flags, Files; public List<string> Paths = new List<string>(); public List<(string Key, string Value)> More; }

        /// <summary>Path with version numbers, dated / numbered / GUID folder names replaced by #, for grouping.</summary>
        static readonly Regex ShapeGuid = new Regex(@"\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?", Util.RX);
        static readonly Regex ShapeHex = new Regex(@"(?<![0-9a-z])(?=[0-9a-f]*\d)[0-9a-f]{8,}(?![0-9a-z])", Util.RX);   // ids, hashes, commit prefixes
        static readonly Regex ShapeLong = new Regex(@"\d{6,}", Util.RX);                                                 // dates, times, counters
        static readonly Regex ShapeVersion = new Regex(@"\d+([._]\d+)+", Util.RX);
        static readonly Regex ShapeLetter = new Regex(@"\p{L}", Util.RX);

        /// <summary>
        /// A path with the numbers in its folder names replaced by "#", for grouping one file's versions, dated or random temp folders.
        /// Only the number or id is replaced (Microsoft.Net.8.0.Runtime.811E9382F7C0D322A19E -> Microsoft.Net.#.Runtime.#, app-1.0.9267 ->
        /// app-#, Claude_5.1.2.0_x64__id -> Claude_#_x64__id), so differently named folders with random ids are not one group; a folder
        /// name that is nothing but numbers and ids becomes "#" as a whole (20261103-075951-1, {GUID}, 13.827.2.6342-1794635423).
        /// </summary>
        internal static string Shape(string p)
        {
            int k = p.LastIndexOf('\\');
            if (k < 0) return p;
            string Seg(string seg)
            {
                var s = ShapeVersion.Replace(ShapeLong.Replace(ShapeHex.Replace(ShapeGuid.Replace(seg, "#"), "#"), "#"), "#");
                return s.IndexOf('#') >= 0 && !ShapeLetter.IsMatch(s) ? "#" : s;
            }
            return string.Join("\\", p.Substring(0, k).Split('\\').Select(Seg)) + p.Substring(k);
        }

        /// <summary>
        /// For lines whose sources only record a file, not an action: what the line's time is. Lines with a run, download, ... need none.
        /// </summary>
        static string TimeMeaning(IEnumerable<string> sources)
        {
            var s = sources.Distinct().ToList();
            // short: the SUMMARY header and the LEGEND say these times are no proof that the program ran
            if (s.All(x => x == "SC")) return "file modified";
            if (s.All(x => x == "AM")) return "Amcache write";
            if (s.All(x => x == "SC" || x == "AM")) return "file modified or Amcache write";
            return null;
        }

        /// <summary>A strong flag on the event or in its file name. Not !known-malware: Autodetect puts it on every event of a file.</summary>
        static bool StrongEvent(TEvent e) =>
            Rules.Strong(Rules.Flags(e.Path)).Count > 0 || (e.Flags != null && Rules.Strong(e.Flags).Any(f => f != Autodetect.Flag));

        /// <summary>Sources whose time is an hour bucket, not when it happened (SRUM): they join the line of the same run.</summary>
        static readonly HashSet<string> HourlySources = new HashSet<string> { "SRU" };

        /// <summary>
        /// (pure) The timeline lines of one file: an event within 2 minutes of the previous one joins its line (one program start, seen by
        /// several sources). Different processes stay apart when flagged: an event with a strong flag and a PID the line does not have
        /// starts a new line, and so does an event with another PID after a line with a strong flag. Events without a PID (Prefetch, BAM,
        /// file events) join the line whose nearest event is closest in time, so they are not given to another process's line. An hour
        /// bucket (SRUM) joins the nearest line within an hour: it is the same run, not a later one.
        /// </summary>
        internal static List<List<TEvent>> Lines(IEnumerable<TEvent> events)
        {
            var all = events.OrderBy(e => e.T).ToList();
            var lines = new List<List<TEvent>>();
            foreach (var chain in Chains(all.Where(e => !HourlySources.Contains(e.Src ?? ""))))
                lines.AddRange(SplitByProcess(chain));
            var hourly = new List<TEvent>();
            foreach (var e in all.Where(e => HourlySources.Contains(e.Src ?? "")))
            {
                var near = lines.Select(l => (Line: l, Gap: l.Min(x => Math.Abs((x.T - e.T).TotalSeconds))))
                                .Where(x => x.Gap <= 3600).OrderBy(x => x.Gap).Select(x => x.Line).FirstOrDefault();
                if (near != null) near.Add(e);
                else hourly.Add(e);
            }
            lines.AddRange(Chains(hourly));   // hour buckets of a file seen by nothing else: as before
            // in time order; events at the same time keep their order (OrderBy is stable)
            return lines.Select(l => l.OrderBy(e => e.T).ToList()).OrderBy(l => l[0].T).ToList();
        }

        /// <summary>Events no more than 2 minutes apart, in time order.</summary>
        static List<List<TEvent>> Chains(IEnumerable<TEvent> events)
        {
            var chains = new List<List<TEvent>>();
            foreach (var e in events.OrderBy(e => e.T))
            {
                if (chains.Count == 0 || (e.T - chains[chains.Count - 1].Last().T).TotalSeconds > 120) chains.Add(new List<TEvent>());
                chains[chains.Count - 1].Add(e);
            }
            return chains;
        }

        /// <summary>One chain's lines: split by process (events with a PID), then each event without a PID to the nearest line.</summary>
        static List<List<TEvent>> SplitByProcess(List<TEvent> chain)
        {
            var lines = new List<List<TEvent>>();
            var pids = new HashSet<int>();   // of the current line
            bool strong = false;
            foreach (var e in chain.Where(e => e.Pid != null))
            {
                bool s = StrongEvent(e);
                if (lines.Count == 0 || (!pids.Contains(e.Pid.Value) && (s || strong)))
                {
                    lines.Add(new List<TEvent>());
                    pids.Clear();
                    strong = false;
                }
                lines[lines.Count - 1].Add(e);
                pids.Add(e.Pid.Value);
                strong |= s;
            }
            if (lines.Count <= 1) return new List<List<TEvent>> { chain.ToList() };
            foreach (var e in chain.Where(e => e.Pid == null))
                lines.OrderBy(l => l.Min(x => Math.Abs((x.T - e.T).TotalSeconds))).First().Add(e);
            return lines;
        }

        /// <summary>
        /// (pure) A line's time: its latest event; on a flagged line (a strong flag on an event, !known-malware included, or in the file
        /// name), the first flagged event (when it happened); for a flag in the file name that is the line's first event.
        /// </summary>
        internal static DateTime LineTime(List<TEvent> line)
        {
            if (line.Any(e => Rules.Strong(Rules.Flags(e.Path)).Count > 0)) return line.Min(e => e.T);
            return line.Where(e => e.Flags != null && Rules.Strong(e.Flags).Count > 0).Select(e => (DateTime?)e.T).Min() ?? line.Max(e => e.T);
        }

        /// <summary>(pure) MergeDetails of events without a PID (all of one process).</summary>
        internal static List<string> MergeDetails(IEnumerable<string> extras) => MergeDetails(extras.Select(x => ((int?)null, x)));

        /// <summary>
        /// (pure) The details of merged events (PID, details), in order, split at "; ". A part is left out when an earlier event gave it
        /// already, or when another event of the same process (same PID, or both without one) has a part that ends with ", " and it:
        /// "parent cmd.exe" (4688) next to "running, pid 5, parent cmd.exe" (PROC). Case does not matter (Explorer.EXE, explorer.exe).
        /// Parts of one event are kept as they are (a command line can contain "; ").
        /// </summary>
        internal static List<string> MergeDetails(IEnumerable<(int? Pid, string Extra)> events)
        {
            var ex = events.Where(e => !string.IsNullOrEmpty(e.Extra)).Distinct()
                           .Select(e => (e.Pid, Parts: e.Extra.Split(new[] { "; " }, StringSplitOptions.None))).ToList();
            var res = new List<string>();
            for (int i = 0; i < ex.Count; i++)
                foreach (var p in ex[i].Parts)
                {
                    bool dup = false;
                    for (int j = 0; j < ex.Count && !dup; j++)
                        if (j != i)
                            dup = ex[j].Parts.Any(q => (j < i && string.Equals(q, p, StringComparison.OrdinalIgnoreCase))
                                                       || (ex[j].Pid == ex[i].Pid && q.EndsWith(", " + p, StringComparison.OrdinalIgnoreCase)));
                    if (!dup) res.Add(p);
                }
            return res;
        }

        /// <summary>Sub-lines with an address: a download's URL, the page it was started from, the referrer.</summary>
        static readonly string[] UrlKeys = { "from", "page", "referrer" };

        /// <summary>A URL without scheme, query and fragment, lowercased: the browser's "host/path" and the Zone.Identifier's full URL match.</summary>
        static string UrlKey(string u)
        {
            var s = Regex.Replace(u ?? "", @"^[a-z][a-z0-9+.-]*://", "", RegexOptions.IgnoreCase);
            int q = s.IndexOfAny(new[] { '?', '#' });
            return (q >= 0 ? s.Substring(0, q) : s).TrimEnd('/').ToLowerInvariant();
        }

        /// <summary>
        /// (pure) The sub-lines of merged events, in order, each once. An address is written once: from, page, referrer in this order,
        /// one of them left out when an earlier one has the same address (the browser's "host/path" before the Zone.Identifier's full
        /// URL, a page or referrer that is the download URL itself, a referrer that is the page).
        /// </summary>
        internal static List<(string Key, string Value)> MergeMore(IEnumerable<(string Key, string Value)> more)
        {
            var all = more.Distinct().ToList();
            var kept = new List<(string Key, string Value)>();
            foreach (var k in UrlKeys)
                foreach (var m in all.Where(m => m.Key == k).OrderBy(m => (m.Value ?? "").Contains("://") ? 1 : 0))
                    if (!kept.Any(x => UrlKey(x.Value) == UrlKey(m.Value))) kept.Add(m);
            var res = new List<(string Key, string Value)>();
            bool placed = false;
            foreach (var m in all)
            {
                if (!UrlKeys.Contains(m.Key)) res.Add(m);
                else if (!placed) { res.AddRange(kept); placed = true; }
            }
            return res;
        }

        /// <summary>
        /// Sub-lines the SUMMARY writes under a line: a download's addresses, a Defender detection's items, the first folder of a drop
        /// folder's group, and the ShimCache time of a copied file.
        /// </summary>
        static readonly HashSet<string> SummaryKeys = new HashSet<string> { "from", "page", "referrer", "file", "process", "resource", "group", "shimcache", "dll", "command" };

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
                    || Rules.Interpreter.IsMatch(path) || Rules.DropLocation(path) || Names.RandomFolder(path) || c.RuntimeLaunchers.Contains(c.RealCase(path))
                    || c.LolbinCopy(path) != null) return null;   // a LOLBin copy (also a validly signed, renamed one) is never hidden
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
                var cl = Lines(g);
                bool Strong(List<TEvent> x) => x.Any(StrongEvent);
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
                    var ex = MergeDetails(x.Select(e => (e.Pid, e.Extra)));
                    ex.InsertRange(0, x.Where(e => e.Known != null).Select(e => e.Known).Distinct());   // the family first
                    if (c.LolbinCopy(path) is string copy) ex.Add(copy);
                    if (TimeMeaning(x.Select(e => e.Src)) is string tm) ex.Add(tm);   // last, so the other details keep their place
                    bool last = x == cl[cl.Count - 1];
                    if (dropped > 0 && last)
                        // several folders: their path: sub-lines below carry the times
                        ex.Add(paths.Count > 1 ? $"+{dropped} more times in between (all paths below)" : $"+{dropped} more times since {first.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture)}");
                    var f = c.F(path, !x.All(e => e.NoHash));
                    var row = new Row
                    {
                        T = LineTime(x), Src = string.Join(" ", x.Select(e => e.Src).Distinct().OrderBy(Order)), Status = f.Status, Obj = f.Path, Files = paths,
                        Details = string.Join("; ", ex), Flags = c.WithLolbinCopy(path, Rules.Flags(path).Concat(x.Where(e => e.Flags != null).SelectMany(e => e.Flags))).Distinct().ToList(),
                        // sub-lines of file events too (script files of a runtime launcher, ...)
                        More = MergeMore(x.Where(e => e.More != null).SelectMany(e => e.More)),
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
                rows.Add(new Row { T = e.T, Src = e.Src, Status = "-", Obj = e.Text, Flags = e.Flags ?? new List<string>(), More = e.More, Aggr = e.Aggr,
                                   Details = string.Join("; ", new[] { e.Extra, TimeMeaning(new[] { e.Src }) }.Where(s => !string.IsNullOrEmpty(s))) });
            rows = rows.OrderBy(x => x.T).ToList();   // oldest first: read it like a story

            var log = new Log();
            log.Heading($"TIMELINE - last {c.Opt.Days} days, oldest first");
            log.Comment("Sources [PF AM ...], status [gone ...] and flags <==== !...: see LEGEND at the end of the log.");
            log.Comment("A file seen by several sources within 2 minutes is one line. A file seen many times: the first and the last time.");
            // one comment per hidden kind (one line would be too long)
            var hiddenParts = new List<string>();
            if (defUpdates > 0) hiddenParts.Add($"{Util.Plural(defUpdates, "run", "runs")} of Defender update packages (AM_Delta_Patch_*.exe)");
            if (signedHidden.Count > 0)
                hiddenParts.Add($"{Util.Plural(signedHidden.Values.Sum(), "run", "runs")} of files validly signed by well-known publishers, without flags: " +
                                string.Join(", ", signedHidden.OrderByDescending(kv => kv.Value).Select(kv => $"{kv.Key} {kv.Value}")));
            for (int i = 0; i < hiddenParts.Count; i++)
                log.Comment((i == 0 ? "Hidden (-nowhitelist lists them): " : "") + hiddenParts[i] + ".");   // each comment line a whole sentence
            var t = new Table("@time", "[sources", "*file or event", "!status", "=details", "<flags");
            if (Aggr.On) TimelineAggr(c, rows);
            foreach (var r in rows)
            {
                t.Add(Log.T(r.T), r.Src, r.Obj, r.Status, r.Details, Rules.FlagCol(r.Flags));
                t.Aggr(r.Aggr);
                foreach (var p in r.Paths) t.More("path", p);
                if (r.More != null) foreach (var m in r.More) t.More(m.Key, m.Value);
            }
            t.WriteTo(log);
            result = rows;
            return log;
        }

        /// <summary>A NEW burst's app folder: two levels below AppData or ProgramData (deeper than a drop location), else null.</summary>
        static readonly Regex BurstRootRx = new Regex(@"^[A-Z]:\\(USERS\\[^\\]+\\APPDATA\\(LOCAL|ROAMING|LOCALLOW)|PROGRAMDATA)\\[^\\]+\\[^\\]+\\", Util.RX);
        internal const int BurstMin = 5;
        internal static readonly TimeSpan BurstSpan = TimeSpan.FromMinutes(10);

        /// <summary>
        /// (pure) The groups of a list of (time, key) that are bursts: BurstMin or more within BurstSpan of the group's first, per key.
        /// Returns the indexes in bursts.
        /// </summary>
        internal static HashSet<int> Bursts(IList<(DateTime T, string Key)> items)
        {
            var res = new HashSet<int>();
            foreach (var g in items.Select((x, i) => (x.T, x.Key, I: i)).Where(x => x.Key != null).GroupBy(x => x.Key, Util.IC))
            {
                var l = g.OrderBy(x => x.T).ToList();
                for (int i = 0; i < l.Count;)
                {
                    int j = i;
                    while (j + 1 < l.Count && l[j + 1].T - l[i].T <= BurstSpan) j++;
                    if (j - i + 1 >= BurstMin) for (int k = i; k <= j; k++) res.Add(l[k].I);
                    i = j + 1;
                }
            }
            return res;
        }

        /// <summary>
        /// Aggressive whitelist (Aggr) on timeline lines without flags: files in updater staging folders (Rules.InUpdaterStaging), and
        /// bursts of new executables an app updater writes: BurstMin or more NEW-only lines within BurstSpan in one app folder two levels
        /// below AppData / ProgramData (no drop location, no random-named folder), each validly signed by the same signer, without
        /// details (no zone, no download). Text events bring their reason along (TEvent.Aggr).
        /// </summary>
        static void TimelineAggr(Ctx c, List<Row> rows)
        {
            bool Plain(Row r) => r.Aggr == null && r.Files != null && r.Files.Count > 0 && Aggr.Harmless(r.Flags);
            foreach (var r in rows.Where(Plain))
                if (r.Files.All(Aggr.Staging)) r.Aggr = "files in updater staging folders";
            string Key(Row r)
            {
                if (!Plain(r) || r.Src != "NEW" || r.Files.Count != 1 || !string.IsNullOrEmpty(r.Details) || (r.More != null && r.More.Count > 0)
                    || !(string.IsNullOrEmpty(r.Status) || r.Status == "-")) return null;
                var p = r.Files[0];
                var m = BurstRootRx.Match(p);
                if (!m.Success || Rules.DropLocation(p) || Names.RandomFolder(p) || !Signature.Applies(p)) return null;
                try
                {
                    var real = c.RealCase(p);
                    if (!File.Exists(real)) return null;
                    var sg = Signature.Check(real);
                    return sg.Valid ? m.Value + "|" + (sg.Signer ?? "").Replace(" (catalog)", "") : null;
                }
                catch { return null; }
            }
            var keys = rows.Select(r => (r.T, Key(r))).ToList();
            foreach (var i in Bursts(keys)) rows[i].Aggr = "new validly signed files of an app update (5+ in one app folder within 10 minutes, one signer)";
        }

        static void Summary(Ctx c, Log log, List<Row> rows)
        {
            log.W();
            log.Heading("SUMMARY - flagged items; details in the sections below");
            log.Comment("time = when it happened, except: ShimCache = the file's modification time (a copied file keeps its old time; a copy seen otherwise has it as a shimcache: detail), Amcache = when Windows wrote the entry.");
            log.Comment("Also not when it happened: Run keys and services = when the key was last changed, tasks and Startup items = file created, log and config files = file last written.");
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
            List<(string Key, string Value)> NoMore = null;
            // the same finding again and again (a service a security product reinstalls, one Defender threat detected many times): one
            // line at its newest time, "+N more times since <first>" like the timeline's lines
            // only findings with a reason the reader can see: a strong flag (FindingFlags, or written after "<====" in the text, as
            // Autodetect and USB DRIVES do). Without one (a remote access tool's folder, an account created, a big upload) the item is in
            // its section only; a flag that is quiet (!lolbin) or a hint is no reason on its own.
            bool Flagged((DateTime? T, string Module, string Text) f)
            {
                var fl = c.FindingFlags.TryGetValue(f.Module + "\n" + f.Text, out var ff) ? ff : new List<string>();
                int cut = (f.Text ?? "").IndexOf(" <==== ", StringComparison.Ordinal);
                if (cut >= 0) fl = fl.Concat(f.Text.Substring(cut + 7).Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries)).ToList();
                // evidence (a strong flag) or context (an info flag: a remote access tool, an account created, ...); same list, by time
                return Rules.Strong(fl).Count > 0 || fl.Any(Rules.Info.Contains);
            }
            var findings = c.Findings.Where(Flagged).GroupBy(f => (f.Module, f.Text)).Select(g =>
            {
                var times = g.Where(f => f.T.HasValue).Select(f => f.T.Value).Distinct().OrderBy(x => x).ToList();
                var f0 = g.First();
                var text = Repeated(f0.Text, times);
                return (T: times.Count > 0 ? times[times.Count - 1] : f0.T, Fields: new[] { Log.T(times.Count > 0 ? times[times.Count - 1] : f0.T), f0.Module, text, null, null,
                                                     c.FindingFlags.TryGetValue(f0.Module + "\n" + f0.Text, out var ff) ? Rules.FlagCol(ff) : null },
                        More: c.FindingMore.TryGetValue(f0.Text ?? "", out var fm) ? fm : NoMore);
            });
            var items = flagged.Select(r => (T: (DateTime?)r.T, Fields: new[] { Log.T(r.T), "timeline " + r.Src, r.Obj, r.Status, r.Details, Rules.FlagCol(Shown(r)) }, More: r.More))
                .Concat(findings)
                .Select((x, i) => (x.T, x.Fields, x.More, I: i))
                .OrderBy(x => x.T.HasValue ? 0 : 1).ThenBy(x => x.T ?? DateTime.MaxValue).ThenBy(x => x.I);
            foreach (var x in items)
            {
                t.Add(x.Fields);
                // a download's addresses and a Defender detection's items: the line itself does not have them
                if (x.More != null) foreach (var m in x.More.Where(m => SummaryKeys.Contains(m.Key))) t.More(m.Key, m.Value);
            }
            t.WriteTo(log, "nothing flagged");
            if (lolbins.Count > 0) log.Wrap("LOLBins run in the last " + c.Opt.Days + " days (normal on many PCs, see the timeline): ", lolbins);
        }

        /// <summary>
        /// (pure) A SUMMARY finding's text for the times it happened (oldest first): itself for one time, else with "+N more times
        /// since &lt;first&gt;" added as its last detail ("item => details; +N more ..." or "item => +N more ...").
        /// </summary>
        internal static string Repeated(string text, IList<DateTime> times)
        {
            if (times == null || times.Count < 2) return text;
            var more = $"+{times.Count - 1} more times since {times[0]:yyyy-MM-dd HH:mm}";
            text = text ?? "";
            // flags written in the text (Autodetect: "... <==== !known-malware") stay at its end
            int cut = text.IndexOf(" <==== ", StringComparison.Ordinal);
            var head = cut >= 0 ? text.Substring(0, cut) : text;
            var tail = cut >= 0 ? text.Substring(cut) : "";
            return (head.Contains(" => ") ? head + "; " + more : head + " => " + more) + tail;
        }

        /// <summary>
        /// (pure) The three parts of a FILES entry: the signature for the line ("valid; signer X; note Z", without the thumbprint), the
        /// file: sub-line ("md5 M; size N; created T; modified T; amcache sha1 S") and the version: sub-line (the version resource,
        /// then "thumbprint T"). Missing values are left out; a part without any value is null.
        /// </summary>
        internal static (string Signature, string File, string Version) FileParts(string signature, string version, string amSha1, string md5, string size,
                                                                                    string created, string modified)
        {
            string Join(IEnumerable<string> parts) { var l = parts.Where(p => !string.IsNullOrEmpty(p)).ToList(); return l.Count > 0 ? string.Join("; ", l) : null; }
            string L(string name, string value) => string.IsNullOrEmpty(value) || value == "-" ? null : name + " " + value;
            var sigParts = (signature ?? "").Split(new[] { "; " }, StringSplitOptions.RemoveEmptyEntries).ToList();
            var thumb = sigParts.FirstOrDefault(p => p.StartsWith("thumbprint ", StringComparison.Ordinal));
            var file = Join(new[] { L("md5", md5), L("size", size), L("created", created), L("modified", modified), L("amcache sha1", amSha1) });
            var ver = Join(new[] { version == "none" ? null : version, thumb });
            return (Join(sigParts.Where(p => p != thumb)), file, ver);
        }

        // where a path in a line can end: the path is followed by " [status]", " => ", ",", ")", ... or the end of the line
        static readonly HashSet<char> PathEnd = new HashSet<char> { ' ', ',', ';', ')', ']', '"', '\'', '|', '<', '>', '\t' };

        /// <summary>
        /// (pure) The keys (FILES paths) the lines name: the full path in a line (case-insensitive), or - for grouped lines
        /// ("folder\ => 14 new files" with "files: a.exe, b.exe" sub-lines) - the folder on its own (followed by a blank, ",", ...)
        /// and the file name in the same item (its line and its indented sub-lines). A bare name elsewhere ("parent services.exe")
        /// does not count.
        /// </summary>
        internal static HashSet<string> ShownFiles(IEnumerable<string> lines, IEnumerable<string> keys)
        {
            var want = new HashSet<string>(keys, Util.IC);
            var byFolder = new Dictionary<string, List<string>>(Util.IC);
            foreach (var k in want)
            {
                int i = k.LastIndexOf('\\');
                if (i < 2 || i == k.Length - 1) continue;
                var f = k.Substring(0, i + 1);
                if (!byFolder.TryGetValue(f, out var l)) byFolder[f] = l = new List<string>();
                l.Add(k);
            }
            var shown = new HashSet<string>(Util.IC);
            var folders = new HashSet<string>(Util.IC);
            var block = new StringBuilder();
            void Flush()
            {
                if (folders.Count > 0)
                {
                    var text = block.ToString();
                    foreach (var f in folders)
                        foreach (var k in byFolder[f])
                            if (!shown.Contains(k) && NamedIn(text, k.Substring(f.Length))) shown.Add(k);
                }
                folders.Clear(); block.Clear();
            }
            foreach (var line in lines)
            {
                if (line == null) continue;
                if (!line.StartsWith(" ", StringComparison.Ordinal)) Flush();   // a new item: its sub-lines are indented
                block.Append(line).Append('\n');
                for (int s = line.IndexOf(":\\", StringComparison.Ordinal); s >= 1; s = line.IndexOf(":\\", s + 2, StringComparison.Ordinal))
                {
                    int st = s - 1;
                    if (!char.IsLetter(line[st]) || (st > 0 && char.IsLetterOrDigit(line[st - 1]))) continue;
                    // every place the path can end: paths hold blanks and parens ("Program Files (x86)")
                    for (int e = s + 2; e <= line.Length; e++)
                    {
                        if (e < line.Length && !PathEnd.Contains(line[e])) continue;
                        var cand = line.Substring(st, e - st);
                        if (want.Contains(cand)) shown.Add(cand);
                        else if (cand.EndsWith("\\", StringComparison.Ordinal) && byFolder.ContainsKey(cand)) folders.Add(cand);
                    }
                }
            }
            Flush();
            return shown;
        }

        /// <summary>The file name as a whole word of an item's text (after a blank, ",", ":", "\" or "(", before a blank, ",", ";", ")" or "]").</summary>
        static bool NamedIn(string text, string name)
        {
            for (int i = text.IndexOf(name, StringComparison.OrdinalIgnoreCase); i >= 0; i = text.IndexOf(name, i + 1, StringComparison.OrdinalIgnoreCase))
            {
                int e = i + name.Length;
                bool before = i == 0 || " ,:\\(\n\t".IndexOf(text[i - 1]) >= 0;
                bool after = e == text.Length || " ,;)]\n\t".IndexOf(text[e]) >= 0;
                if (before && after) return true;
            }
            return false;
        }

        /// <summary>
        /// (pure) The FILES keys to list, sorted, and how many the whitelist leaves out: a validly signed file no section shows (the
        /// programs of the services and drivers Persistence hides, ...). Anything else - unsigned, a bad signature, no access, not an
        /// executable - stays listed. signer(key) = the signature description ("valid; signer X; ..."), null if none.
        /// </summary>
        internal static (List<string> Keep, int Hidden) FilesToList(IEnumerable<string> keys, Func<string, string> signer, ISet<string> shown, bool whitelist)
        {
            var keep = new List<string>(); int hidden = 0;
            foreach (var k in keys.Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(k => k, StringComparer.OrdinalIgnoreCase))
            {
                var sg = signer(k);
                bool valid = sg != null && (sg == "valid" || sg.StartsWith("valid;", StringComparison.Ordinal));
                if (whitelist && valid && !shown.Contains(k)) { hidden++; continue; }
                keep.Add(k);
            }
            return (keep, hidden);
        }

        /// <summary>Media, subtitles and images, and the Recycle Bin's $I index files: their hashes say nothing about malware.</summary>
        static readonly Regex DataFile = new Regex(
            @"\.(MKV|MP4|AVI|MOV|WMV|M4V|WEBM|M2TS|MPG|MPEG|VOB|FLV|MP3|M4A|FLAC|WAV|OGG|OPUS|AAC|WMA|SRT|ASS|SSA|SUB|IDX|VTT|JPG|JPEG|PNG|GIF|BMP|WEBP|HEIC|TIF|TIFF|NEF|CR2)$" +
            @"|\\\$RECYCLE\.BIN\\[^\\]+\\\$I[^\\]+$", Util.RX);

        /// <summary>
        /// (pure) Why the aggressive whitelist leaves a FILES entry out, or null: a file no unmarked line names (only lines -aggressive
        /// hides name it, or none), or a plain data file. Never a flagged file (path flags, marks such as a Defender detection, LOLBin copy).
        /// </summary>
        internal static string FileAggr(string key, bool namedByUnmarked, bool marked)
        {
            if (marked || Rules.Strong(Rules.Flags(key)).Count > 0) return null;
            if (DataFile.IsMatch(key)) return "media, subtitle, image and Recycle Bin index files";
            if (!namedByUnmarked) return "files only hidden lines name";
            return null;
        }

        /// <summary>
        /// (pure) AMCACHE FILES entries in bulk folders, with the reason: a folder with AmcacheBulk or more entries (toolchains such as
        /// msys64, Git\usr\bin, R tools: an inventory of a whole folder) of which no unmarked line names one, none flagged or marked.
        /// </summary>
        internal static Dictionary<string, string> AmcacheBulkFolders(IEnumerable<string> keys, ISet<string> named, Func<string, bool> marked)
        {
            var res = new Dictionary<string, string>(Util.IC);
            foreach (var g in keys.Where(k => k.LastIndexOf('\\') > 2).GroupBy(k => k.Substring(0, k.LastIndexOf('\\') + 1), Util.IC))
            {
                var l = g.ToList();
                if (l.Count < AmcacheBulk || Rules.DropLocation(l[0]) || Names.RandomFolder(l[0])
                    || l.Any(k => named.Contains(k) || marked(k) || Rules.Strong(Rules.Flags(k)).Count > 0)) continue;
                foreach (var k in l) res[k] = "Amcache-only files in " + g.Key;
            }
            return res;
        }

        internal const int AmcacheBulk = 20;

        static void Files(Ctx c, Log log)
        {
            var all = c.Sha256.Keys.Concat(c.Signer.Keys).Concat(c.ToHash.Keys).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            HashSet<string> shown = null, shownUnmarked = null;
            if (Rules.Whitelist)
            {
                shown = ShownFiles(log.Lines, all);
                shownUnmarked = ShownFiles(Aggr.Unmarked(log.Lines), all);   // aggressive: what stays when marked records go
                // an app execution alias shows the program it starts (its status is that program's)
                foreach (var (alias, target) in c.AliasTargets())
                {
                    if (shown.Contains(alias)) shown.Add(target);
                    if (shownUnmarked.Contains(alias)) shownUnmarked.Add(target);
                }
            }
            var (files, hidden) = FilesToList(all, k => c.Signer.TryGetValue(k, out var s) ? s : null, shown ?? new HashSet<string>(), Rules.Whitelist);
            if (files.Count > 0 || hidden > 0)
            {
                log.W();
                log.Heading($"FILES - {c.Opt.Algo}, signature and version of the files as they are on disk now");
                log.Comment("Three lines per file. The line: hash and signature: valid / invalid / revoked / expired / unsigned, \"(catalog)\" = signed through a Windows catalog; signer; note.");
                log.Comment("file: md5 = MD5 of the file now; size = bytes; created, modified = file times in LOCAL time of this PC (as FRST shows them), not UTC; amcache sha1 = the file when Windows recorded it (differs if replaced since).");
                log.Comment("version: file version, description, product, company, original name; thumbprint = certificate SHA1.");
                if (hidden > 0)
                    log.Comment($"Hidden: {Util.Plural(hidden, "validly signed file", "validly signed files")} no section above shows (Windows drivers and system files, programs of trusted services); -nowhitelist lists them.");
                var t = new Table("*file", ">" + c.Opt.Algo.ToLowerInvariant(), "signature");
                foreach (var k in files)
                {
                    c.HashFile(k);
                    c.Sha256.TryGetValue(k, out var h); c.Signer.TryGetValue(k, out var sg); c.Version.TryGetValue(k, out var vi); c.AmSha1.TryGetValue(k, out var am);
                    c.Md5.TryGetValue(k, out var md5); bool meta = c.Meta.TryGetValue(k, out var fm);
                    var (sig, fileLine, versionLine) = FileParts(sg, vi, am?.ToUpperInvariant(), md5, meta ? fm.Size.ToString() : null,
                        meta ? Log.T(Util.FrstLocal(fm.Created, c.LocalOffset)) : null, meta ? Log.T(Util.FrstLocal(fm.Modified, c.LocalOffset)) : null);
                    t.Add(k, h ?? "not hashed", sig);
                    t.More("file", fileLine);
                    t.More("version", versionLine);
                    if (Aggr.On) t.Aggr(FileAggr(k, shownUnmarked.Contains(k), c.MarksOf(k).Count > 0 || c.LolbinCopy(k) != null));
                }
                t.WriteTo(log);
            }
            // not the files the whitelist left out of FILES either: they are known good
            var amOnly = c.AmSha1.Where(kv => !c.Sha256.ContainsKey(kv.Key) && !c.Signer.ContainsKey(kv.Key) && !c.ToHash.ContainsKey(kv.Key)).ToList();
            if (amOnly.Count > 0)
            {
                log.W();
                log.Heading("AMCACHE FILES - SHA1 from Amcache of files not listed above (the file when Windows recorded it)");
                var t = new Table("*file", ">sha1");
                var bulk = Aggr.On ? AmcacheBulkFolders(amOnly.Select(kv => kv.Key), ShownFiles(Aggr.Unmarked(log.Lines), amOnly.Select(kv => kv.Key)),
                                                        k => c.MarksOf(k).Count > 0 || c.LolbinCopy(k) != null)
                                   : new Dictionary<string, string>();
                foreach (var kv in amOnly.OrderBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase))
                {
                    t.Add(kv.Key, kv.Value.ToUpperInvariant());
                    if (bulk.TryGetValue(kv.Key, out var why)) t.Aggr(why);
                }
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
