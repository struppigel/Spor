using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace Spor.Modules
{
    /// <summary>
    /// Defender: detections, actions, setting changes (exclusions, real-time protection off), tamper protection, history deleted;
    /// MPLog: files Defender looked up in the cloud (unknown files, usually right when they ran or were written), detection lines;
    /// event logs cleared.
    /// </summary>
    class Security : IModule
    {
        public string Id => "defender";
        public string Name => "DEFENDER";
        public string Description => "detections, setting changes, cloud lookups (MPLog), cleared event logs";

        const string DefLog = "Microsoft-Windows-Windows Defender/Operational";
        Ctx c;

        public void Execute(Ctx ctx)
        {
            c = ctx;
            Events();
            MpLog();
            Exclusions();
            Cleared();
        }

        static string CleanPath(string p)
        {
            if (string.IsNullOrEmpty(p)) return p;
            var parts = p.Split(';').Select(x => Regex.Replace(x.Trim(), @"^(file|process|regkey|containerfile|amsi|behavior|startup|webfile):_", "", Util.RX)).Where(x => x.Length > 0).ToList();
            return string.Join("; ", parts);
        }

        /// <summary>
        /// (pure) The items of a detection's cleaned Path field ("a; b; process: C:\x.exe, pid:5:123; pid:5,ProcessStart:456"), one per sub-line:
        /// file: a file (also "x.zip->inner.exe"), process: a process (with its pid), resource: anything else (registry key, ...).
        /// A "pid:N,ProcessStart:M" piece of a process already listed is left out.
        /// </summary>
        internal static List<(string Key, string Value)> Resources(string paths)
        {
            var parts = (paths ?? "").Split(new[] { "; " }, StringSplitOptions.RemoveEmptyEntries).Select(x => x.Trim()).Where(x => x.Length > 0).ToList();
            var pids = new HashSet<string>(parts.Where(x => x.StartsWith("process: ", StringComparison.OrdinalIgnoreCase))
                                                .Select(x => Regex.Match(x, @"\bpid:(\d+)").Groups[1].Value).Where(x => x.Length > 0));
            var res = new List<(string, string)>();
            foreach (var x in parts)
            {
                var pm = Regex.Match(x, @"^pid:(\d+)[,:]", Util.RX);
                if (x.StartsWith("process: ", StringComparison.OrdinalIgnoreCase)) res.Add(("process", x.Substring("process: ".Length)));
                else if (pm.Success && pids.Contains(pm.Groups[1].Value)) continue;
                else if (pm.Success) res.Add(("process", x));
                else if (Rules.DrivePath.IsMatch(x) || x.StartsWith(@"\\", StringComparison.Ordinal)) res.Add(("file", x));
                else res.Add(("resource", x));
            }
            return res.Distinct().ToList();
        }

        /// <summary>A process: item ("C:\x.exe, pid:5:123") is the process named (C:\x.exe).</summary>
        static bool SameProcess(string item, string proc) =>
            item.Equals(proc, StringComparison.OrdinalIgnoreCase) || item.StartsWith(proc + ",", StringComparison.OrdinalIgnoreCase);

        /// <summary>Files a detection names that still exist get hashed (listed in FILES); "x.zip->inner.exe" = the archive.</summary>
        void HashNamed(string paths)
        {
            foreach (var part in (paths ?? "").Split(new[] { "; " }, StringSplitOptions.RemoveEmptyEntries))
            {
                var p = part.Trim(); int arrow = p.IndexOf("->", StringComparison.Ordinal);
                if (arrow > 0) p = p.Substring(0, arrow);
                if (!Rules.DrivePath.IsMatch(p)) continue;
                try { if (File.Exists(p)) c.F(p); } catch { }
            }
        }

        void Events()
        {
            c.Out.Sub("Defender events (oldest first)");
            var ev = Ev.Query(DefLog, Ev.Ids(1006, 1007, 1008, 1013, 1015, 1116, 1117, 1118, 1119, 5001, 5004, 5007, 5010, 5012, 5013), c.Since, 5000, c.Err);
            ev.Reverse();   // the newest are read (up to the limit), listed oldest first
            int routine = 0; var purged = new List<DateTime>();
            var et = new Table("@time", "[event", "<flags", "*what");
            foreach (var e in ev)
            {
                var m = Ev.Msg(e); var t = e.TimeCreated?.ToUniversalTime();
                string text; var fl = new List<string>(); bool find = true;
                List<(string Key, string Value)> more = null;
                switch (e.Id)
                {
                    case 1006: case 1007: case 1008: case 1015: case 1116: case 1117: case 1118: case 1119:
                        {
                            find = e.Id != 1117 && e.Id != 1007;   // "action taken" repeats the detection
                            var what = e.Id == 1116 || e.Id == 1006 || e.Id == 1015 ? "detected" : e.Id == 1117 || e.Id == 1007 ? "action taken" : "action FAILED";
                            var name = Ev.Field(m, "Name"); var path = CleanPath(Ev.Field(m, "Path")); var act = Ev.Field(m, "Action"); var proc = Ev.Field(m, "Process Name");
                            // the line: the threat and what was done; every detected item on a sub-line of its own
                            more = Resources(path).Select(x => (x.Key, Rules.Fix(x.Value))).ToList();
                            var rest = new List<string>();
                            if (!string.IsNullOrEmpty(act) && act != "Not Applicable") rest.Add("action " + act);
                            // the process that touched the file, unless it is the detected process itself
                            if (!string.IsNullOrEmpty(proc) && proc != "Unknown" && !more.Any(x => x.Key == "process" && SameProcess(x.Value, proc))) rest.Add("process " + proc);
                            text = $"Defender {what}: {name}" + (rest.Count > 0 ? " => " + string.Join("; ", rest) : "");
                            if (e.Id == 1118 || e.Id == 1119 || e.Id == 1008) fl.Add("!not-removed");
                            HashNamed(path);
                            break;
                        }
                    case 1013: text = "Defender detection history deleted"; find = false; if (t.HasValue) purged.Add(t.Value); break;
                    case 5001: text = "Defender real-time protection turned OFF"; fl.Add("!defender-off"); break;
                    case 5010: text = "Defender antispyware scanning turned OFF"; fl.Add("!defender-off"); break;
                    case 5012: text = "Defender antivirus scanning turned OFF"; fl.Add("!defender-off"); break;
                    case 5013: text = "Tamper protection blocked a change: " + Util.Clip(Ev.Field(m, "Changed Value") ?? Ev.Field(m, "Value") ?? m, 140); break;
                    case 5004: text = "Defender real-time protection configuration changed: " + Util.Clip(Ev.Field(m, "Feature Name") ?? "", 60) + " " + Util.Clip(Ev.Field(m, "Configuration") ?? "", 40); find = false; break;
                    default:   // 5007: only exclusions and protection turned off; signature/config hashes etc. are routine
                        {
                            var nv = Ev.Field(m, "New value") ?? Ev.Field(m, "New Value") ?? "";
                            var ov = Ev.Field(m, "Old value") ?? Ev.Field(m, "Old Value") ?? "";
                            if (Regex.IsMatch(nv + " " + ov, @"\\Exclusions\\", Util.RX))
                            {
                                fl.Add("!defender-exclusion");
                                text = nv.Length > 0 ? "Defender exclusion added or changed: " + nv : "Defender exclusion removed: " + ov;
                            }
                            else if (Regex.IsMatch(nv, @"\\(DisableRealtimeMonitoring|DisableBehaviorMonitoring|DisableIOAVProtection|DisableOnAccessProtection|DisableScriptScanning|DisableAntiSpyware|DisableAntiVirus|DisableBlockAtFirstSeen|DisableArchiveScanning|TamperProtection)\s*=\s*0x[1-9]", Util.RX)
                                     && !Regex.IsMatch(nv, @"\\EcsConfigs\\|\\Features\\Controls\\", Util.RX))
                            {
                                fl.Add("!defender-off");
                                text = "Defender protection setting changed: " + nv;
                            }
                            else { routine++; e.Dispose(); continue; }
                            break;
                        }
                }
                text = Rules.Fix(text);
                et.Add(Log.T(t), e.Id.ToString(), Rules.FlagCol(fl), text);
                if (more != null) foreach (var x in more) et.More(x.Key, x.Value);
                c.Event(t, "DEF", null, text: text, flags: fl, more: more);
                if (find && fl.Count == 0) c.Find(t, text, more);   // flagged events are in the summary through the timeline
                e.Dispose();
            }
            if (purged.Count > 0)
                c.Find(purged.Max(), $"Defender detection history deleted {Util.Plural(purged.Count, "time", "times")} since {Log.T(purged.Min())} (Defender also does this by itself after the retention time, default 15 days)");
            if (routine > 0) c.Out.Comment($"{routine} routine setting changes not listed (signature and configuration updates)");
            et.WriteTo(c.Out, "no detections or important setting changes in the last " + c.Opt.Days + " days");
        }

        static readonly Regex Sdn = new Regex(@"^(?<t>\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z?)\s.*?SDN:Issuing SDN query for (?<p>.+?) \(", Util.RX);
        static readonly Regex Det = new Regex(@"^(?<t>\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z?)\s+(?<r>.*\b(DETECTIONEVENT|DETECTION_ADD|DETECTION)\b(?! State).*)$", RegexOptions.CultureInvariant);   // upper case only: "Detection State" lines are routine
        static readonly Regex Sha2 = new Regex(@"sha2=([0-9a-f]{64})", Util.RX);

        void MpLog()
        {
            var dir = Path.Combine(Ctx.Env("ProgramData") ?? @"C:\ProgramData", @"Microsoft\Windows Defender\Support");
            c.Out.Sub("Defender support log (MPLog): unknown files Defender looked up in the cloud",
                "Usually when the file was run or written. Outside trusted locations; first and last time per file.");
            string[] logs;
            try { logs = Directory.GetFiles(dir, "MPLog-*.log"); } catch (Exception e) { c.Out.None("cannot read " + dir + ": " + e.Message); return; }
            var hits = new Dictionary<string, (DateTime First, DateTime Last, int N, string Sha)>(Util.IC);
            var det = new List<(DateTime T, string R)>();
            foreach (var f in logs)
            {
                try
                {
                    foreach (var l in Util.Lines(f))
                    {
                        var m = Sdn.Match(l);
                        if (m.Success)
                        {
                            var t = Time(m.Groups["t"].Value); if (t == null || t < c.Since) continue;
                            var p = c.Long(c.DevicePath(m.Groups["p"].Value.Trim()));   // MPLog writes \\?\C:\...
                            if (Rules.Whitelist && !Keep(p)) continue;
                            var sh = Sha2.Match(l);
                            hits[p] = hits.TryGetValue(p, out var h)
                                ? (t < h.First ? t.Value : h.First, t > h.Last ? t.Value : h.Last, h.N + 1, h.Sha ?? (sh.Success ? sh.Groups[1].Value : null))
                                : (t.Value, t.Value, 1, sh.Success ? sh.Groups[1].Value : null);
                            continue;
                        }
                        var d = Det.Match(l);
                        if (d.Success) { var t = Time(d.Groups["t"].Value); if (t != null && t >= c.Since) det.Add((t.Value, d.Groups["r"].Value.Trim())); }
                    }
                }
                catch (Exception e) { c.Err.Add("MPLog " + Path.GetFileName(f) + ": " + e.Message); }
            }
            var mt = new Table("@last seen", "first seen", "times", "!status", "<flags", "*file");
            foreach (var kv in hits.OrderBy(kv => kv.Value.Last))
            {
                var h = kv.Value; var f = c.F(kv.Key);
                mt.Add(Log.T(h.Last), Log.T(h.First), h.N.ToString(), f.Status, Rules.FlagCol(Rules.Flags(kv.Key)), f.Path);
                c.Event(h.First, "MPL", kv.Key);
                if (h.N > 1 && (h.Last - h.First).TotalMinutes > 2) c.Event(h.Last, "MPL", kv.Key);
            }
            mt.WriteTo(c.Out);
            if (det.Count > 0)
            {
                c.Out.Sub("MPLog detection lines");
                var dt = new Table("@time", "*line");
                foreach (var d in det.OrderBy(x => x.T))
                {
                    dt.Add(Log.T(d.T), d.R);
                    c.Event(d.T, "DEF", null, text: "MPLog: " + d.R);
                }
                dt.WriteTo(c.Out);
            }
        }

        static DateTime? Time(string s) =>
            DateTime.TryParse(s, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.AdjustToUniversal | System.Globalization.DateTimeStyles.AssumeUniversal, out var t) ? t : (DateTime?)null;

        bool Keep(string p) => !c.TrustedFile(p);   // Defender asked the cloud about it: hide only signed files in Windows / Program Files

        void Exclusions()
        {
            c.Out.Sub("Defender exclusions (current)");
            bool denied = false;
            var xt = new Table("@time", "[kind", "*exclusion");
            foreach (var kind in new[] { "Paths", "Extensions", "Processes", "IpAddresses", "TemporaryPaths" })
            {
                try
                {
                    using (var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows Defender\Exclusions\" + kind))
                    {
                        if (k == null) continue;
                        var names = k.GetValueNames();
                        if (names.Length == 0) continue;
                        var t = Native.LastWrite(k);
                        foreach (var n in names) { xt.Add(Log.T(t), kind, Rules.Fix(n)); if (t < c.Since) c.Find(t, $"Defender exclusion ({kind}): {Rules.Fix(n)}", "key changed"); }   // newer changes: timeline DEF line
                        c.Event(t, "DEF", null, text: $"Defender {kind.ToLowerInvariant()} exclusions changed (now {names.Length}: {Util.Clip(string.Join(", ", names), 100)})", flags: new List<string> { "!defender-exclusion" });
                    }
                }
                catch (UnauthorizedAccessException) { denied = true; }
                catch (System.Security.SecurityException) { denied = true; }
            }
            xt.WriteTo(c.Out, denied ? "the exclusion list is hidden from administrators on this Windows version (see the 5007 events above)" : null);
        }

        void Cleared()
        {
            c.Out.Sub("Event logs cleared");
            var ev = Ev.Query("System", "EventID=104", c.Since, 500, c.Err).Concat(Ev.Query("Security", "EventID=1102", c.Since, 500, c.Err)).ToList();
            var lt = new Table("@time", "<flags", "*log");
            foreach (var e in ev.OrderBy(e => e.TimeCreated))
            {
                var t = e.TimeCreated?.ToUniversalTime();
                var log = e.Id == 1102 ? "Security" : Ev.P(e, 2) is string s && s.Length > 0 ? s : Util.Clip(Ev.Msg(e), 80);
                var text = "event log cleared: " + log;
                var fl = new List<string> { "!log-cleared" };
                lt.Add(Log.T(t), Rules.FlagCol(fl), log);
                c.Event(t, "LOG", null, text: text, flags: fl);
                if (fl.Count == 0) c.Find(t, text);
                e.Dispose();
            }
            lt.WriteTo(c.Out);
        }
    }
}
