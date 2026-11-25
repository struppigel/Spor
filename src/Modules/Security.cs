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
        /// <summary>(time, threat) of the Defender detection events (Events): an MPLog line of the same detection is not a second timeline line.</summary>
        readonly List<(DateTime T, string Threat)> detected = new List<(DateTime, string)>();

        /// <summary>(pure) An MPLog detection line that names a threat of a Defender event within 5 minutes of it.</summary>
        internal static bool SameAsEvent(DateTime? t, string line, IEnumerable<(DateTime T, string Threat)> events) =>
            t.HasValue && events.Any(e => !string.IsNullOrEmpty(e.Threat) && Math.Abs((e.T - t.Value).TotalMinutes) <= 5
                                          && (line ?? "").IndexOf(e.Threat, StringComparison.OrdinalIgnoreCase) >= 0);

        // ---------------- Root certificates ----------------

        public const string RootCertFlag = "!root-cert";
        public const string CustomRootFlag = "!custom-root";

        /// <summary>
        /// (pure) The certificate in a SystemCertificates "Blob" value: a list of properties (DWORD id, DWORD reserved, DWORD length,
        /// data); id 32 is the encoded certificate. null when there is none.
        /// </summary>
        internal static byte[] CertFromBlob(byte[] blob)
        {
            if (blob == null) return null;
            for (int i = 0; i + 12 <= blob.Length;)
            {
                int id = BitConverter.ToInt32(blob, i), len = BitConverter.ToInt32(blob, i + 8);
                if (len < 0 || len > blob.Length - i - 12) return null;   // no int overflow on a crafted length
                if (id == 32) { var cert = new byte[len]; Array.Copy(blob, i + 12, cert, 0, len); return cert; }
                i += 12 + len;
            }
            return null;
        }

        /// <summary>
        /// (pure) The SHA1 thumbprints (hex, upper case) in Windows' list of trusted roots (EncodedCtl, a signed certificate trust list):
        /// each entry starts with its thumbprint as a 20-byte OCTET STRING (04 14). Other 20-byte strings in the list (key IDs) match no
        /// certificate's thumbprint. Empty when there is no list.
        /// </summary>
        internal static HashSet<string> CtlThumbprints(byte[] ctl)
        {
            var res = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (ctl == null) return res;
            for (int i = 0; i + 22 <= ctl.Length; i++)
                if (ctl[i] == 0x04 && ctl[i + 1] == 0x14)
                    res.Add(BitConverter.ToString(ctl, i + 2, 20).Replace("-", ""));
            return res;
        }

        /// <summary>(pure) One of Windows' own roots (Microsoft, old timestamping CAs): by name and only when old (before 2020), so a new
        /// self-signed "CN=Microsoft ..." root someone added is still reported.</summary>
        internal static bool WindowsOwnRoot(string subject, DateTime notBefore) => WindowsRoot.IsMatch(subject ?? "") && notBefore.Year < 2020;

        /// <summary>Roots Windows itself has in its Root store (not from the AuthRoot program): never custom.</summary>
        static readonly Regex WindowsRoot = new Regex(@"Microsoft|Thawte Timestamping|Symantec Enterprise Mobile Root|VeriSign Time Stamping|NO LIABILITY ACCEPTED", Util.RX);

        /// <summary>
        /// Root certificates someone added: in the machine's and every user's Root store (and their Group Policy / enterprise stores),
        /// self-signed and not in Windows' AuthRoot list. A man-in-the-middle proxy installs one to read HTTPS (WEEVILPROXY: certutil
        /// -addstore root); AV web shields, Fiddler and developer tools too. Added in the time window: !root-cert; older: the context
        /// flag !custom-root (an infection can be older than the window).
        /// </summary>
        void Roots()
        {
            c.Out.Sub("Root certificates added (not Windows' own)", "time = when the store key was written; self-signed roots outside Windows' AuthRoot list");
            var t = new Table("@added", "[store", "<flags", "*subject", "=details");
            var authRoot = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            try { using (var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\SystemCertificates\AuthRoot\Certificates")) if (k != null) authRoot.UnionWith(k.GetSubKeyNames()); } catch { }
            // the whole program list (authroot.stl as Windows keeps it): roots Windows downloads when first needed are in ROOT, not AuthRoot
            try { using (var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\SystemCertificates\AuthRoot\AutoUpdate")) authRoot.UnionWith(CtlThumbprints(k?.GetValue("EncodedCtl") as byte[])); } catch { }
            var stores = new List<(string Name, RegistryKey Root, string Path)>
            {
                ("machine", Registry.LocalMachine, @"SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates"),
                ("machine policy", Registry.LocalMachine, @"SOFTWARE\Policies\Microsoft\SystemCertificates\Root\Certificates"),
                ("enterprise", Registry.LocalMachine, @"SOFTWARE\Microsoft\EnterpriseCertificates\Root\Certificates"),
            };
            foreach (var h in c.Hives) stores.Add(("user " + h.User, h.Root, @"Software\Microsoft\SystemCertificates\Root\Certificates"));
            foreach (var (name, root, path) in stores)
                try
                {
                    using (var k = root.OpenSubKey(path))
                    {
                        if (k == null) continue;
                        foreach (var thumb in k.GetSubKeyNames())
                        {
                            if (authRoot.Contains(thumb)) continue;
                            using (var ck = k.OpenSubKey(thumb))
                            {
                                var der = CertFromBlob(ck?.GetValue("Blob") as byte[]);
                                if (der == null) continue;
                                System.Security.Cryptography.X509Certificates.X509Certificate2 x;
                                try { x = new System.Security.Cryptography.X509Certificates.X509Certificate2(der); } catch { continue; }
                                // Windows' own roots by name only when old: a new self-signed "CN=Microsoft ..." root is someone's
                                if (x.Subject != x.Issuer || WindowsOwnRoot(x.Subject, x.NotBefore)) continue;
                                var when = Native.LastWrite(ck);
                                var fl = new List<string> { when.HasValue && when >= c.Since ? RootCertFlag : CustomRootFlag };
                                var details = $"thumbprint {thumb}; valid {x.NotBefore:yyyy-MM-dd} to {x.NotAfter:yyyy-MM-dd}";
                                t.Add(Log.T(when), name, Rules.FlagCol(fl), Rules.Fix(x.Subject), details);
                                c.Find(when, $"root certificate ({name}): {Rules.Fix(x.Subject)}", details, fl);
                            }
                        }
                    }
                }
                catch (Exception e) { c.Err.Add($"root certificates ({name}): {e.Message}"); }
            t.WriteTo(c.Out, "none");
        }

        // ---------------- Hidden Settings pages ----------------

        public const string SettingsHiddenFlag = "!settings-hidden";

        /// <summary>Settings pages malware hides so the user cannot see or undo it (its proxy, Defender, the reset that would remove it).</summary>
        static readonly HashSet<string> EvidencePages = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "network-proxy", "recovery", "windowsdefender", "windowsupdate", "windowsupdate-action", "troubleshoot", "network-status",
        };

        /// <summary>(pure) The pages a SettingsPageVisibility value hides that malware hides (evidence), and its other pages. "showonly:"
        /// hides every other page: evidence.</summary>
        internal static (List<string> Evidence, List<string> Other) SettingsHidden(string value)
        {
            var v = (value ?? "").Trim();
            var ev = new List<string>(); var other = new List<string>();
            int colon = v.IndexOf(':');
            if (colon < 0) return (ev, other);
            var mode = v.Substring(0, colon).Trim().ToLowerInvariant();
            var pages = v.Substring(colon + 1).Split(';').Select(p => p.Trim()).Where(p => p.Length > 0).ToList();
            if (mode == "showonly") { ev.Add("everything but " + string.Join(", ", pages)); return (ev, other); }
            if (mode != "hide") return (ev, other);
            foreach (var p in pages) (EvidencePages.Contains(p) ? ev : other).Add(p);
            return (ev, other);
        }

        /// <summary>SettingsPageVisibility (machine and every user): hidden Settings pages.</summary>
        void SettingsPages()
        {
            const string Key = @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer";
            c.Out.Sub("Hidden Settings pages (SettingsPageVisibility)", "time = key last changed");
            var t = new Table("@changed", "[scope", "<flags", "*value");
            var keys = new List<(string Name, RegistryKey Root)> { ("machine", Registry.LocalMachine) };
            foreach (var h in c.Hives) keys.Add(("user " + h.User, h.Root));
            foreach (var (name, root) in keys)
                try
                {
                    using (var k = root.OpenSubKey(Key))
                    {
                        var v = Convert.ToString(k?.GetValue("SettingsPageVisibility"));
                        if (string.IsNullOrWhiteSpace(v)) continue;
                        var (ev, other) = SettingsHidden(v);
                        var when = Native.LastWrite(k);
                        c.Observe("registry", @"Policies\Explorer\SettingsPageVisibility=" + v, when);
                        var fl = new List<string> { ev.Count > 0 ? SettingsHiddenFlag : "!settings-changed" };
                        t.Add(Log.T(when), name, Rules.FlagCol(fl), Rules.Fix(v));
                        c.Find(when, $"Settings pages hidden ({name}): {Rules.Fix(v)}", ev.Count > 0 ? "hides " + string.Join(", ", ev) : null, fl);
                    }
                }
                catch (Exception e) { c.Err.Add("SettingsPageVisibility " + name + ": " + e.Message); }
            t.WriteTo(c.Out, "none");
        }

        public void Execute(Ctx ctx)
        {
            c = ctx;
            Events();
            MpLog();
            Exclusions();
            Cleared();
            Roots();
            SettingsPages();
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
            bool inCmd = false;
            foreach (var x in parts)
            {
                var pm = Regex.Match(x, @"^pid:(\d+)[,:]", Util.RX);
                // a command line (CmdLine:_...) can contain "; " itself: the parts after it belong to it until the next item
                bool newItem = pm.Success || x.StartsWith("process: ", StringComparison.OrdinalIgnoreCase) || Rules.DrivePath.IsMatch(x)
                               || x.StartsWith(@"\\", StringComparison.Ordinal) || Regex.IsMatch(x, @"^[a-z]+:_", Util.RX);
                if (inCmd && !newItem) { var last = res[res.Count - 1]; res[res.Count - 1] = (last.Item1, last.Item2 + "; " + x); continue; }
                inCmd = x.StartsWith("CmdLine:", StringComparison.OrdinalIgnoreCase);
                if (x.StartsWith("process: ", StringComparison.OrdinalIgnoreCase)) res.Add(("process", x.Substring("process: ".Length)));
                else if (pm.Success && pids.Contains(pm.Groups[1].Value)) continue;
                else if (pm.Success) res.Add(("process", x));
                else if (Rules.DrivePath.IsMatch(x) || x.StartsWith(@"\\", StringComparison.Ordinal)) res.Add(("file", x));
                else res.Add(("resource", x));
            }
            return res.Distinct().ToList();
        }

        /// <summary>
        /// (pure) A 5007 "New value" that turns protection off: a Disable* value set to non-zero, or TamperProtection set to 0x0 or 0x4
        /// (off; 0x1 and 0x5 are on, as a fresh install or an update writes them). Not the EcsConfigs / Features\Controls values.
        /// </summary>
        internal static bool DefenderOff(string nv)
        {
            nv = nv ?? "";
            if (Regex.IsMatch(nv, @"\\EcsConfigs\\|\\Features\\Controls\\", Util.RX)) return false;
            if (Regex.IsMatch(nv, @"\\TamperProtection\s*=\s*0x0*[04]\s*$", Util.RX)) return true;
            return Regex.IsMatch(nv, @"\\(DisableRealtimeMonitoring|DisableBehaviorMonitoring|DisableIOAVProtection|DisableOnAccessProtection|DisableScriptScanning|DisableAntiSpyware|DisableAntiVirus|DisableBlockAtFirstSeen|DisableArchiveScanning)\s*=\s*0x[1-9]", Util.RX);
        }

        public const string DetectedFlag = "!defender-detected";
        public const string InExclusionFlag = "!in-defender-exclusion";

        /// <summary>A "\Device\HarddiskVolumeN\..." resource as the file on its drive, or null (not a device path, or no drive for it).</summary>
        string DeviceFile(string resource)
        {
            if (!Regex.IsMatch(resource ?? "", @"^\\Device\\HarddiskVolume\d+\\", Util.RX)) return null;
            var p = c.DevicePath(resource);
            return Rules.DrivePath.IsMatch(p ?? "") ? p : null;
        }

        /// <summary>(pure) The file of a detection's file: / process: item: "C:\a.zip->x.exe" is the archive, "C:\x.exe, pid:5:123" the program.</summary>
        internal static string DetectedPath(string item)
        {
            var p = item ?? "";
            int arrow = p.IndexOf("->", StringComparison.Ordinal);
            if (arrow > 0) p = p.Substring(0, arrow);
            int pid = p.IndexOf(", pid:", StringComparison.OrdinalIgnoreCase);
            if (pid > 0) p = p.Substring(0, pid);
            return p.Trim().Trim('"');
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
                            if (t.HasValue && !string.IsNullOrEmpty(name)) detected.Add((t.Value, name));
                            // the line: the threat and what was done; every detected item on a sub-line of its own
                            // a resource on a volume device ("\Device\HarddiskVolume3\Users\x\a.exe") is the file on its drive
                            var items = Resources(path).Select(x => x.Key == "resource" && DeviceFile(x.Value) is string df ? (Key: "file", Value: df) : (Key: x.Key, Value: x.Value))
                                                       .Distinct().ToList();
                            more = items.Select(x => (x.Key, Rules.Fix(x.Value))).ToList();
                            // every timeline line of a detected file (and of a detected process) gets !defender-detected; not a signed
                            // program in Windows / Program Files a behavior detection names (svchost.exe: what ran in it was detected).
                            // The raw paths (more has them as the log shows them: <U+202E> for a bidi character), as the events have them.
                            foreach (var x in items.Where(x => x.Key == "file" || x.Key == "process"))
                            {
                                var dp = DetectedPath(x.Value);
                                if (x.Key == "process" && Rules.InTrustedLocation(dp) && c.SignedOk(dp)) continue;
                                c.MarkPath(dp, DetectedFlag);
                            }
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
                    // something tried to turn Defender off (Tamper Protection stopped it): an attempt is as telling as success
                    case 5013: text = "Tamper protection blocked a change: " + Util.Clip(Ev.Field(m, "Changed Value") ?? Ev.Field(m, "Value") ?? m, 140); fl.Add("!defender-off"); break;
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
                            else if (DefenderOff(nv))
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
                var de = c.Event(t, "DEF", null, text: text, flags: fl, more: more);
                // aggressive whitelist: each "detection history deleted" event (the SUMMARY line counts them, with the first and last time)
                const string purgeWhy = "Defender \"detection history deleted\" events (the SUMMARY counts them)";
                if (e.Id == 1013 && Aggr.On && fl.Count == 0) { et.Aggr(purgeWhy); if (de != null) de.Aggr = purgeWhy; }
                // flagged events are in the summary through the timeline; a detection is a finding with its flag
                if (find && fl.Count == 0)
                {
                    if (e.Id == 1006 || e.Id == 1015 || e.Id == 1116) c.Find(t, text, null, new List<string> { DetectedFlag }, more);
                    else c.Find(t, text, more);
                }
                e.Dispose();
            }
            if (purged.Count > 0)
                c.Find(purged.Max(), $"Defender detection history deleted {Util.Plural(purged.Count, "time", "times")} since {Log.T(purged.Min())} (Defender also does this by itself after the retention time, default 15 days)",
                       null, Rules.InfoFlag("!history-deleted"));
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
                    // the same detection as a Defender event (1116/1117, within 5 minutes, same threat) is on the timeline already
                    if (!SameAsEvent(d.T, d.R, detected)) c.Event(d.T, "DEF", null, text: "MPLog: " + d.R);
                }
                dt.WriteTo(c.Out);
            }
        }

        static DateTime? Time(string s) =>
            DateTime.TryParse(s, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.AdjustToUniversal | System.Globalization.DateTimeStyles.AssumeUniversal, out var t) ? t : (DateTime?)null;

        bool Keep(string p) => !c.TrustedFile(p);   // Defender asked the cloud about it: hide only signed files in Windows / Program Files

        void Exclusions()
        {
            c.Out.Sub("Defender exclusions (current)", "kind: Paths, Processes, ... ; (policy) = set through Group Policy / the Policies key, where malware also writes them");
            bool denied = false;
            var xt = new Table("@time", "[kind", "<flags", "*exclusion");
            var flag = new List<string> { "!defender-exclusion" };
            foreach (var (root, policy) in new[] { (@"SOFTWARE\Microsoft\Windows Defender\Exclusions\", false), (@"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\", true) })
            foreach (var kind in new[] { "Paths", "Extensions", "Processes", "IpAddresses", "TemporaryPaths" })
            {
                try
                {
                    using (var k = Registry.LocalMachine.OpenSubKey(root + kind))
                    {
                        if (k == null) continue;
                        var names = k.GetValueNames();
                        if (names.Length == 0) continue;
                        var t = Native.LastWrite(k);
                        var shown = kind + (policy ? " (policy)" : "");
                        foreach (var n in names)
                        {
                            xt.Add(Log.T(t), shown, Rules.FlagCol(flag), Rules.Fix(n));
                            if (t < c.Since) c.Find(t, $"Defender exclusion ({shown}): {Rules.Fix(n)}", null, flag);   // time = key changed; newer changes: timeline DEF line
                            // the files in an excluded folder, an excluded program: Defender does not look at them
                            var x = Environment.ExpandEnvironmentVariables(n.Trim().Trim('"'));
                            if (kind == "Paths" && Rules.DrivePath.IsMatch(x)) c.MarkFolder(x, InExclusionFlag, unsigned: true);
                            else if (kind == "Processes" && Rules.DrivePath.IsMatch(x)) c.MarkPath(x, InExclusionFlag);
                        }
                        c.Event(t, "DEF", null, text: $"Defender {kind.ToLowerInvariant()} exclusions{(policy ? " (policy)" : "")} changed (now {names.Length}: {Util.Clip(string.Join(", ", names), 100)})", flags: flag);
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
