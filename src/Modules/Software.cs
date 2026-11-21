using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace Spor.Modules
{
    /// <summary>
    /// Software installed, updated or removed in the time window:
    ///  - Uninstall keys (machine 64/32-bit and per user): name, version, publisher, install date (day only), install folder,
    ///    uninstaller; time = when the key was last written (install or update)
    ///  - Windows Installer events (Application log, MsiInstaller 1033/1034/11707/11724): installs and removals with exact times,
    ///    also of software that is gone now.
    /// Fake installers, bundled adware and remote access tools show up here; per-user installs need no admin rights.
    /// </summary>
    class Software : IModule
    {
        public string Id => "software";
        public string Name => "SOFTWARE";
        public string Description => "programs installed, updated or removed recently";

        Ctx c;

        public void Execute(Ctx ctx)
        {
            c = ctx;
            Installed();
            Msi();
            Store();
        }

        /// <summary>
        /// Store / MSIX apps added, registered, removed or failed in the time window (AppXDeploymentServer log 400 = done, 401 = failed).
        /// Packages installed from a web page (App Installer, ms-appinstaller links) are a known malware delivery: flagged !from-web.
        /// With the whitelist, Microsoft packages (validly signed by Microsoft, or in Windows\SystemApps) that came from the Store or
        /// Windows Update are counted, not listed.
        /// </summary>
        void Store()
        {
            c.Out.Sub($"Store and MSIX apps: added, registered, removed or failed in the last {c.Opt.Days} days (AppXDeploymentServer log)",
                "times = how often this operation ran for the package in the time window (updates and re-registrations repeat it).\n" +
                "from = where the package came from (a file, a Store URL or a web page); signer = the package signature now (gone = removed or updated since).");
            var ev = Ev.Query("Microsoft-Windows-AppXDeploymentServer/Operational", Ev.Ids(400, 401), c.Since, 20000, c.Err);
            var ops = new Dictionary<string, (DateTime T, DateTime First, int N, string Op, bool Failed, string Pkg, string Name, string From, string Src, bool Full, string Err)>(Util.IC);
            foreach (var e in ev)
            {
                try
                {
                    var t = e.TimeCreated?.ToUniversalTime(); if (!t.HasValue) continue;
                    var x = e.ToXml();
                    string D(string n) { var m = Regex.Match(x, "<Data Name='" + n + "'>([^<]*)</Data>"); return m.Success ? System.Net.WebUtility.HtmlDecode(m.Groups[1].Value).Trim() : ""; }
                    var msg = Ev.Msg(e) ?? "";
                    var op = Regex.Match(msg, @"Deployment (\w+) operation", RegexOptions.IgnoreCase) is var om && om.Success ? om.Groups[1].Value : "operation " + D("DeploymentOperation");
                    var pkg = D("PackageFullName"); if (pkg.Length == 0) continue;
                    if (Regex.IsMatch(op, "^(Stage|DeStage|OnDemandRegisterOperation)$", Util.RX)) continue;   // download / cleanup bookkeeping, always with an Add or Register
                    var err = e.Id == 401 ? (Regex.Match(msg, @"error (0x[0-9A-F]{8})", RegexOptions.IgnoreCase) is var em && em.Success ? em.Groups[1].Value : "failed") : null;
                    var key = pkg + "|" + op + "|" + e.Id;
                    if (ops.TryGetValue(key, out var o)) ops[key] = (o.T > t.Value ? o.T : t.Value, o.First < t.Value ? o.First : t.Value, o.N + 1, op, o.Failed, pkg, o.Name, o.From, o.Src, o.Full, o.Err);
                    else ops[key] = (t.Value, t.Value, 1, op, e.Id == 401, pkg, D("PackageDisplayName"), D("Path"), D("PackageSourceUri"), D("HasFullTrust").Equals("true", StringComparison.OrdinalIgnoreCase), err);
                }
                catch { }
                finally { e.Dispose(); }
            }
            // signer and folder are long (a GUID, the package's full name again): sub-lines
            var t2 = new Table("@last", "[operation", "*package", "=display name", "first", "times", "from", "source", "full trust", "!status", "<flags");
            int hidden = 0;
            // the package now: its own folder, or (removed / updated) the newest folder of the same app (name + publisher ID) seen in the log
            string Family(string pkg) { var m = Regex.Match(pkg, @"^([^_]+)_.*_([a-z0-9]{13})$", Util.RX); return m.Success ? m.Groups[1].Value + "_" + m.Groups[2].Value : pkg; }
            string Dir(string pkg)
            {
                foreach (var d in new[] { Path.Combine(Ctx.Env("ProgramFiles") ?? @"C:\Program Files", "WindowsApps", pkg), Path.Combine(c.WinDir, "SystemApps", pkg) })
                    if (Directory.Exists(d)) return d;
                return null;
            }
            var famDir = new Dictionary<string, string>(Util.IC);
            foreach (var o in ops.Values.OrderByDescending(v => v.T)) { var f = Family(o.Pkg); if (!famDir.ContainsKey(f) || famDir[f] == null) famDir[f] = Dir(o.Pkg); }
            (string Signer, string Status, bool Valid) Sig(string dir)
            {
                if (dir == null) return ("-", "gone", false);
                if (dir.StartsWith(c.WinDir, StringComparison.OrdinalIgnoreCase)) return ("Windows (SystemApps)", "-", true);
                // a package has AppxManifest.xml, a bundle AppxMetadata\AppxBundleManifest.xml; both are covered by the package signature
                var man = new[] { "AppxManifest.xml", @"AppxMetadata\AppxBundleManifest.xml" }.Select(m => Path.Combine(dir, m)).FirstOrDefault(File.Exists);
                if (man == null) return ("-", "unsigned", false);
                var sg = Signature.Check(man);
                return (sg.Signer ?? "-", sg.Valid ? "-" : sg.Status == "unsigned" || sg.Status == "no access" ? sg.Status : sg.Status + " signature", sg.Valid);
            }
            foreach (var o in ops.Values.OrderBy(v => v.T))
            {
                var dir = Dir(o.Pkg);
                var now = Sig(dir);
                var fam = dir == null && famDir.TryGetValue(Family(o.Pkg), out var fd) && fd != null ? Sig(fd) : now;   // removed/updated: judge by the current version
                var who = fam.Signer.Replace(" (package)", "");
                // Microsoft: signed by Microsoft, or Microsoft's publisher ID in the package name (Windows only installs a package whose
                // signing certificate matches the publisher the ID is derived from)
                bool ms = (fam.Valid && Regex.IsMatch(who, @"^Microsoft (Corporation|Windows)|^Windows \(SystemApps\)", Util.RX)) || Regex.IsMatch(o.Pkg, @"_(8wekyb3d8bbwe|cw5n1h2txyewy)$", Util.RX);
                // installed from a web page: flagged unless the app is validly signed by a well-known publisher (its own updater downloads from its site)
                var web = Regex.IsMatch(o.Src + " " + o.From, @"^https?://|\shttps?://|ms-appinstaller:", Util.RX) && !Regex.IsMatch(o.Src + " " + o.From, @"(^|\.)(microsoft|windowsupdate|msftconnecttest)\.com/", Util.RX);
                var fl = new List<string>(); if (web && !(fam.Valid && Rules.TrustedSigners.Contains(who))) fl.Add("!from-web");
                if (Rules.Whitelist && ms && fl.Count == 0) { hidden += o.N; continue; }   // Microsoft's own packages, also failed updates ("in use")
                // the package's install folder (FRST "Packages:" names it); for a package that is gone, the folder it had
                var folder = dir ?? Path.Combine(Ctx.Env("ProgramFiles") ?? @"C:\Program Files", "WindowsApps", o.Pkg);
                t2.Add(Log.T(o.T), o.Op + (o.Failed ? " FAILED " + o.Err : ""), Rules.Fix(o.Pkg), Rules.Fix(o.Name), o.N > 1 ? Log.T(o.First) : "-", o.N.ToString(),
                       Rules.Fix(Source(o.From)), Rules.Fix(Source(o.Src)), o.Full ? "yes" : "-", now.Status, Rules.FlagCol(fl));
                var signer = dir != null ? now.Signer : fam.Signer != "-" ? fam.Signer + " (newer version)" : "-";
                if (signer != "-") t2.More("signer", signer);
                t2.More("folder", Rules.Fix(folder));
                c.Event(o.T, "INS", null, null, fl.Count > 0 ? fl : null,
                        text: $"Store app {o.Op.ToLowerInvariant()}{(o.Failed ? " FAILED" : "")}: {Rules.Fix(o.Pkg)}" + (o.Name.Length > 0 ? $" ({Rules.Fix(o.Name)})" : "") +
                              (o.Src.Length > 0 ? ", from " + Rules.Fix(Source(o.Src)) : ""),
                        more: new List<(string Key, string Value)> { ("folder", Rules.Fix(folder)) });
            }
            if (hidden > 0) c.Out.Comment($"{hidden} operations on Microsoft packages (Store and Windows updates, also failed ones) not listed; -nowhitelist lists them.");
            t2.WriteTo(c.Out, "no Store or MSIX app operations in the time window" + (hidden > 0 ? " except Microsoft's own" : ""));
        }

        /// <summary>(pure) Where a package came from, for the log: a Windows Update URL ("x-windowsupdate://GUID/GUID/hash") as "Windows Update".</summary>
        internal static string Source(string s) =>
            s != null && s.StartsWith("x-windowsupdate://", StringComparison.OrdinalIgnoreCase) ? "Windows Update" : s;

        void Installed()
        {
            c.Out.Sub($"Installed programs, installed or updated in the last {c.Opt.Days} days (Uninstall keys)",
                "time = when the entry was last written (install or update); install date = the day the installer wrote (if any).\n" +
                "program = the uninstaller, or the program the entry shows as its icon; its status says whether it is signed.");
            // folder and key on sub-lines (folder:, key:): the line would get too long with them
            var t = new Table("@time", "[scope", "*name", "version", "publisher", "install date", ">program", "!status", "<flags", "hidden");
            // Prefix = the key as FRST writes it in Addition's "Installed Programs" lines: HKLM\...\<subkey>, HKLM-x32\...\<subkey>, HKU\<SID>\...\<subkey>
            var keys = new List<(string Scope, RegistryKey Root, string Path, string Prefix)>
            {
                ("machine", Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", @"HKLM\...\"),
                ("machine 32-bit", Registry.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall", @"HKLM-x32\...\")
            };
            foreach (var h in c.Hives) keys.Add(("user " + h.User, h.Root, @"Software\Microsoft\Windows\CurrentVersion\Uninstall", @"HKU\" + h.P.Sid + @"\...\"));
            var rows = new List<(DateTime T, string Scope, string Name, string Ver, string Pub, string Date, string Folder, string Prog, string Status, List<string> Fl, string Key, bool Hidden)>();
            int total = 0;
            var batch = new Dictionary<int, List<string>>();   // line index -> key: lines of a grouped install (each with its entry's name and version)
            foreach (var (scope, root, path, prefix) in keys)
            {
                try
                {
                    using (var u = root.OpenSubKey(path))
                    {
                        if (u == null) continue;
                        foreach (var n in u.GetSubKeyNames())
                            using (var k = u.OpenSubKey(n))
                            {
                                if (k == null) continue;
                                total++;
                                var name = S(k, "DisplayName");
                                if (name.Length == 0) continue;   // hidden components without a name
                                var lw = Native.LastWrite(k);
                                var idate = InstallDate(S(k, "InstallDate"));
                                // Autodetect sees every entry, also older ones: "name | version | publisher", the folder and the icon program
                                var swItem = $"installed program {name} {S(k, "DisplayVersion")}".TrimEnd() + (S(k, "Publisher").Length > 0 ? $" ({S(k, "Publisher")})" : "") + $", key {prefix}{n}";
                                c.Observe("software", $"{name} | {S(k, "DisplayVersion")} | {S(k, "Publisher")}", lw ?? idate, swItem);
                                var loc = S(k, "InstallLocation").Trim('"').TrimEnd('\\');
                                if (Rules.DrivePath.IsMatch(loc)) c.Observe("path", loc + "\\", lw ?? idate, swItem);
                                var ico = Regex.Replace(S(k, "DisplayIcon"), @",-?\d+$", "").Trim('"');
                                if (Rules.DrivePath.IsMatch(ico)) c.Observe("path", ico, lw ?? idate);
                                bool recent = (lw.HasValue && lw.Value >= c.Since) || (idate.HasValue && idate.Value >= c.Since.Date);
                                if (!recent) continue;
                                // the program that represents the entry: DisplayIcon (exe) or the uninstaller
                                var icon = Regex.Replace(S(k, "DisplayIcon"), @",-?\d+$", "").Trim('"');
                                var cmd = icon.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? icon : S(k, "UninstallString");
                                var prog = cmd.Length > 0 ? Cmd.Program(cmd, c.WinDir) : "";
                                var msi = Regex.IsMatch(prog, @"\\msiexec\.exe$", Util.RX);
                                var pf = prog.Length > 0 && !msi && Rules.DrivePath.IsMatch(prog) ? c.F(prog) : (msi ? "Windows Installer (msiexec)" : "-", "-");
                                var folder = S(k, "InstallLocation").Trim('"').TrimEnd('\\');
                                var fl = prog.Length > 0 && !msi ? Rules.Flags(prog) : new List<string>();
                                var when = lw ?? idate.Value;
                                bool hiddenEntry = int.TryParse(Convert.ToString(k.GetValue("SystemComponent")), out var sc) && sc == 1;   // FRST: "Hidden"
                                rows.Add((when, scope, name, S(k, "DisplayVersion"), S(k, "Publisher"), idate.HasValue ? idate.Value.ToString("yyyy-MM-dd") : "-",
                                          folder.Length > 0 ? Rules.Fix(c.RealCase(folder)) + "\\" : "-", pf.Item1, pf.Item2, fl, prefix + n, hiddenEntry));
                            }
                    }
                }
                catch (Exception e) { c.Err.Add(scope + " Uninstall keys: " + e.Message); }
            }
            c.Out.Comment($"{total} Uninstall entries, {rows.Count} written in the last {c.Opt.Days} days.");
            // one SDK or driver package installs dozens of entries at once: 4+ entries of one publisher within 5 minutes without
            // flags or signature problems are one line with every name and version
            var groups = new List<List<(DateTime T, string Scope, string Name, string Ver, string Pub, string Date, string Folder, string Prog, string Status, List<string> Fl, string Key, bool Hidden)>>();
            foreach (var r in rows.OrderBy(r => r.Scope).ThenBy(r => r.Pub).ThenBy(r => r.T))
            {
                var last = groups.Count > 0 ? groups[groups.Count - 1] : null;
                if (last != null && last[0].Scope == r.Scope && last[0].Pub == r.Pub && (r.T - last[last.Count - 1].T).TotalMinutes <= 5) last.Add(r);
                else groups.Add(new List<(DateTime, string, string, string, string, string, string, string, string, List<string>, string, bool)> { r });
            }
            var lines = new List<(DateTime T, string[] F)>();
            foreach (var g in groups)
            {
                bool clean = g.All(r => r.Fl.Count == 0 && (r.Status == "-" || r.Status == "gone"));
                if (g.Count >= 4 && clean)
                {
                    var tl = g.Max(r => r.T);
                    lines.Add((tl, new[] { Log.T(tl), g[0].Scope, $"{g.Count} entries from {(g[0].Pub.Length > 0 ? g[0].Pub : "no publisher")}", "-", "-", "-", "-", "-", "-", "-", "-", "-" }));
                    // each key: sub-line carries its entry's own name and version (an FRST Installed Programs line can match one entry)
                    string KeyLine(string key, string name, string ver) =>
                        key + (name.Length > 0 ? "; name " + name : "") + (ver.Length > 0 ? "; version " + ver : "");
                    // no list of names: every key: line names its entry
                    batch[lines.Count - 1] = g.Select(r => KeyLine(r.Key, r.Name, r.Ver)).ToList();
                    c.Event(tl, "INS", null, text: $"installed or updated: {g.Count} entries from {(g[0].Pub.Length > 0 ? g[0].Pub : "no publisher")}",
                            more: g.Select(r => ("key", KeyLine(r.Key, r.Name, r.Ver))).ToList());
                    continue;
                }
                foreach (var r in g)
                {
                    lines.Add((r.T, new[] { Log.T(r.T), r.Scope, r.Name, r.Ver, r.Pub, r.Date, r.Folder, r.Prog, r.Status, Rules.FlagCol(r.Fl), r.Key, r.Hidden ? "yes" : "-" }));
                    c.Event(r.T, "INS", null, null, r.Fl.Count > 0 ? r.Fl : null, more: new List<(string Key, string Value)> { ("key", r.Key) },
                            text: $"installed or updated: {r.Name} {r.Ver}".TrimEnd() + (r.Pub.Length > 0 ? $" ({r.Pub})" : "") + (r.Scope.StartsWith("user") ? ", per user" : ""));
                }
            }
            foreach (var (l, i) in lines.Select((l, i) => (l, i)).OrderBy(x => x.l.T))
            {
                // F: time, scope, name, version, publisher, install date, folder, program, status, flags, key, hidden
                t.Add(l.F[0], l.F[1], l.F[2], l.F[3], l.F[4], l.F[5], l.F[7], l.F[8], l.F[9], l.F[11]);
                if (batch.TryGetValue(i, out var keyLines)) foreach (var k in keyLines) t.More("key", k);
                else
                {
                    if (l.F[6] != "-") t.More("folder", l.F[6]);
                    if (l.F[10] != "-") t.More("key", l.F[10]);
                }
            }
            t.WriteTo(c.Out);
        }

        /// <summary>
        /// The data of a Windows Installer 1033 / 1034 event: product name, version, (language,) status, manufacturer, in this order;
        /// null when the event has fewer fields or no name. The message text is localized, the data is not.
        /// </summary>
        static (string Name, string Version, string Status, string Maker)? MsiData(System.Diagnostics.Eventing.Reader.EventRecord e)
        {
            try
            {
                var p = e.Properties;
                if (p == null || p.Count < 5) return null;
                string V(int i) { var s = Util.Clip(p[i].Value); return s == "(NULL)" ? "" : s; }
                return V(0).Length > 0 ? (V(0), V(1), V(3), V(4)) : ((string, string, string, string)?)null;
            }
            catch { return null; }
        }

        /// <summary>Windows Installer events: exact install and removal times, also for software that is gone now.</summary>
        void Msi()
        {
            c.Out.Sub($"Windows Installer: installs and removals in the last {c.Opt.Days} days (Application log)",
                "1033 = installed, 1034 = removed, 11708 = install failed; status 0 = success.");
            var ev = Ev.Query("Application", "Provider[@Name='MsiInstaller'] and (" + Ev.Ids(1033, 1034, 11708) + ")", c.Since, 5000, c.Err);
            ev.Reverse();   // listed oldest first
            var t = new Table("@time", "[event", "*what", "=user", "name", "product code");
            var seen = new HashSet<string>(Util.IC);
            foreach (var e in ev)
            {
                var tm = e.TimeCreated?.ToUniversalTime();
                var msg = Util.Clip(Ev.Msg(e));
                string user = null;
                try { user = e.UserId != null ? Who(e.UserId.Value) : null; } catch { }
                if (!seen.Add(Log.T(tm) + "|" + msg)) { e.Dispose(); continue; }
                // 1033 / 1034: the event data (name, version, language, status, manufacturer), the same in every Windows language;
                // the English labels of the message only as a fallback
                var data = (e.Id == 1033 || e.Id == 1034) ? MsiData(e) : null;
                string F(string n) { var m = Regex.Match(msg, n + @":\s*(.*?)\.(\s+[A-Z][\w ]+:|\s*$)"); return m.Success ? m.Groups[1].Value.Trim() : ""; }
                var what = e.Id == 1033 ? "installed" : e.Id == 1034 ? "removed" : "install FAILED";
                var name = data?.Name ?? F("Product Name");
                var ver = data?.Version ?? F("Product Version");
                var maker = data?.Maker ?? F("Manufacturer");
                var st = data?.Status ?? F("(?:Installation|Removal) success or error status");
                var text = name.Length > 0
                    ? $"{what}: {name} {ver}".TrimEnd() + (maker.Length > 0 ? $" ({maker})" : "") + (st.Length > 0 && st != "0" ? $", status {st} (failed)" : "")
                    : $"{what}: " + Regex.Replace(msg, @"^Product:\s*", "", RegexOptions.IgnoreCase);
                var code = ProductCode(e);   // = the product's Uninstall subkey (FRST: HKLM\...\{GUID})
                t.Add(Log.T(tm), e.Id.ToString(), text, user, name, code);
                c.Event(tm, "INS", null, code != null ? "product code " + code : null, text: "Windows Installer " + text);
                e.Dispose();
            }
            t.WriteTo(c.Out, "no Windows Installer installs or removals in the time window");
        }

        static readonly Regex Guid = new Regex(@"\{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\}", Util.RX);

        /// <summary>
        /// The MSI product code of an MsiInstaller event: Windows stores "({GUID})" as the event's binary data (hex of the ASCII text);
        /// some events also have it in a text field. null if not found.
        /// </summary>
        static string ProductCode(System.Diagnostics.Eventing.Reader.EventRecord e)
        {
            try
            {
                var x = e.ToXml();
                var b = Regex.Match(x, @"<Binary>([0-9A-Fa-f]+)</Binary>");
                if (b.Success)
                {
                    var hex = b.Groups[1].Value;
                    var bytes = Enumerable.Range(0, hex.Length / 2).Select(i => Convert.ToByte(hex.Substring(i * 2, 2), 16)).ToArray();
                    foreach (var text in new[] { System.Text.Encoding.ASCII.GetString(bytes), System.Text.Encoding.Unicode.GetString(bytes) })
                        if (Guid.Match(text) is var m && m.Success) return m.Value;
                }
                foreach (Match d in Regex.Matches(x, @"<Data>([^<]*)</Data>"))
                    if (Guid.Match(d.Groups[1].Value) is var m && m.Success) return m.Value;
            }
            catch { }
            return null;
        }

        string Who(string sid) => sid == "S-1-5-18" ? "SYSTEM" : sid == "S-1-5-19" ? "LOCAL SERVICE" : sid == "S-1-5-20" ? "NETWORK SERVICE" : c.UserOf(sid);

        static string S(RegistryKey k, string n) => (Convert.ToString(k.GetValue(n)) ?? "").Trim();

        static DateTime? InstallDate(string s) =>
            DateTime.TryParseExact(s, "yyyyMMdd", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var d) ? d : (DateTime?)null;
    }
}
