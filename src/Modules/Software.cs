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
    ///  - cached Windows Installer packages (C:\Windows\Installer\*.msi) that install into LocalAppData and run a script host, cmd,
    ///    PowerShell or a script of their own as a custom action (RenLoader's fake vendor apps that start PavinLoader).
    /// Fake installers, bundled adware and remote access tools show up here; per-user installs need no admin rights.
    /// </summary>
    class Software : IModule
    {
        public string Id => "software";
        public string Name => "SOFTWARE";
        public string Description => "programs installed, updated or removed recently";

        Ctx c;
        /// <summary>The Uninstall subkeys read (Installed): a Windows Installer event of one of them is not a second Autodetect value.</summary>
        readonly HashSet<string> uninstallKeys = new HashSet<string>(Util.IC);

        public void Execute(Ctx ctx)
        {
            c = ctx;
            Installed();
            Msi();
            Cached();
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
            var merged = new Dictionary<string, StoreLine>(Util.IC);   // package -> its timeline line (operations merged)
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
                // one install runs several operations (provision, add, register) within seconds: one timeline line for them
                var op = OpName(o.Op);
                if (!o.Failed && fl.Count == 0 && merged.TryGetValue(o.Pkg, out var m) && (o.T - m.Ev.T).TotalMinutes <= 2)
                {
                    if (!m.Ops.Contains(op)) m.Ops.Add(op);
                    if (m.Name.Length == 0) m.Name = o.Name;
                    if (m.Src.Length == 0) m.Src = o.Src;
                    m.Ev.Text = StoreText(m.Ops, o.Pkg, m.Name, m.Src);
                    continue;
                }
                int before = c.Events.Count;
                c.Event(o.T, "INS", null, null, fl.Count > 0 ? fl : null,
                        text: StoreText(new List<string> { op + (o.Failed ? " FAILED" : "") }, o.Pkg, o.Name, o.Src),
                        more: new List<(string Key, string Value)> { ("folder", Rules.Fix(folder)) });
                if (!o.Failed && fl.Count == 0 && c.Events.Count > before)
                    merged[o.Pkg] = new StoreLine { Ev = c.Events[c.Events.Count - 1], Ops = new List<string> { op }, Name = o.Name, Src = o.Src };
            }
            if (hidden > 0) c.Out.Comment($"{hidden} operations on Microsoft packages (Store and Windows updates, also failed ones) not listed; -nowhitelist lists them.");
            t2.WriteTo(c.Out, "no Store or MSIX app operations in the time window" + (hidden > 0 ? " except Microsoft's own" : ""));
        }

        class StoreLine { public TEvent Ev; public List<string> Ops; public string Name; public string Src; }

        /// <summary>(pure) An AppXDeploymentServer operation for the timeline: "ProvisionPackageOperation" -> "provision", "Add" -> "add".</summary>
        internal static string OpName(string op) => Regex.Replace(op ?? "", "PackageOperation$", "", RegexOptions.IgnoreCase).ToLowerInvariant();

        /// <summary>(pure) "Store app add, register: package (name), from source".</summary>
        internal static string StoreText(List<string> ops, string pkg, string name, string src) =>
            $"Store app {string.Join(", ", ops)}: {Rules.Fix(pkg)}" + (name.Length > 0 ? $" ({Rules.Fix(name)})" : "") + (src.Length > 0 ? ", from " + Rules.Fix(Source(src)) : "");

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
                                uninstallKeys.Add(n);   // an MSI product's subkey is its product code
                                var swItem = $"installed program {NameVersion(name, S(k, "DisplayVersion"))}" + (S(k, "Publisher").Length > 0 ? $" ({S(k, "Publisher")})" : "") + $", key {prefix}{n}";
                                c.Observe("software", $"{name} | {S(k, "DisplayVersion")} | {S(k, "Publisher")}", lw ?? idate, swItem);
                                var loc = InstallFolder(S(k, "InstallLocation"));
                                if (Rules.DrivePath.IsMatch(loc)) { c.Observe("path", loc + "\\", lw ?? idate, swItem); c.Relate(swItem, loc + "\\"); }
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
                                var folder = InstallFolder(S(k, "InstallLocation"));
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
                            text: $"installed or updated: {NameVersion(r.Name, r.Ver)}" + (r.Pub.Length > 0 ? $" ({r.Pub})" : "") + (r.Scope.StartsWith("user") ? ", per user" : ""));
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
                var name = data?.Name ?? F("Product Name");
                var ver = data?.Version ?? F("Product Version");
                var maker = data?.Maker ?? F("Manufacturer");
                var st = data?.Status ?? F("(?:Installation|Removal) success or error status");
                bool failed = e.Id == 11708 || (st.Length > 0 && st != "0");
                // a 1033 with an error status is a failed install, not "installed: ..., status 1603 (failed)"
                var what = e.Id == 1034 ? (failed ? "removal FAILED" : "removed") : failed ? "install FAILED" : "installed";
                var text = name.Length > 0
                    ? $"{what}: {NameVersion(name, ver)}" + (maker.Length > 0 ? $" ({maker})" : "") + (failed && st.Length > 0 && st != "0" ? $", status {st}" : "")
                    : $"{what}: " + Regex.Replace(msg, @"^Product:\s*", "", RegexOptions.IgnoreCase);
                var code = ProductCode(e);   // = the product's Uninstall subkey (FRST: HKLM\...\{GUID})
                t.Add(Log.T(tm), e.Id.ToString(), text, user, name, code);
                // Autodetect sees a product installed and removed again within the window too (no Uninstall key left to read);
                // one still installed it has seen through its Uninstall key (one SUMMARY line, not two)
                if (name.Length > 0 && !failed && (code == null || !uninstallKeys.Contains(code)))
                    c.Observe("software", $"{name} | {ver} | {maker}", tm, $"Windows Installer {what}: {NameVersion(name, ver)}" +
                              (maker.Length > 0 ? $" ({maker})" : "") + (code != null ? ", product code " + code : ""));
                // the timeline has one line per install: not a second one for the same product within 5 minutes (the Uninstall key's
                // "installed or updated" line, or the 11708 next to a failed 1033)
                bool twin = code != null && tm.HasValue && c.Events.Any(x => x.Src == "INS" && Math.Abs((x.T - tm.Value).TotalMinutes) <= 5
                    && ((x.More != null && x.More.Any(m => m.Key == "key" && m.Value.EndsWith("\\" + code, StringComparison.OrdinalIgnoreCase)) && !failed)
                        || (x.Extra == "product code " + code && failed && (x.Text ?? "").Contains("FAILED"))));
                if (!twin) c.Event(tm, "INS", null, code != null ? "product code " + code : null, text: "Windows Installer " + text);
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

        /// <summary>(pure) InstallLocation as a folder without the last "\": quotes and blanks off, "C:/Riot Games/x/" with backslashes.</summary>
        internal static string InstallFolder(string s)
        {
            s = (s ?? "").Trim().Trim('"').Trim();
            if (Regex.IsMatch(s, @"^[a-z]:/", Util.RX)) s = s.Replace('/', '\\');
            return s.TrimEnd('\\');
        }

        /// <summary>Script hosts and shells a custom action can start.</summary>
        static readonly Regex ScriptHost = new Regex(@"(^|[\\/""\s\]])(wscript|cscript|cmd|powershell|pwsh|mshta)(\.exe)?(?=[\s""]|$)", Util.RX);   // "]": [SystemFolder]cmd.exe
        static readonly Regex ScriptFile = new Regex(@"\.(wsf|vbs|vbe|js|jse|hta|ps1|cmd|bat)$", Util.RX);
        /// <summary>A formatted file reference in a custom action: [#FileKey] (its path) or [!FileKey] (its short path).</summary>
        static readonly Regex FileRef = new Regex(@"\[[#!]([^\]]+)\]");

        /// <summary>The long name of an MSI name ("SHORT~1.EXE|Long name.exe"; DefaultDir: "target:source").</summary>
        static string MsiLong(string n)
        {
            n = (n ?? "").Split(':')[0];
            var bar = n.IndexOf('|');
            return bar >= 0 ? n.Substring(bar + 1) : n;
        }

        internal sealed class MsiHit
        {
            public List<string> Actions = new List<string>();   // "Action: command"
            public List<string> Folders = new List<string>();   // below LocalAppDataFolder, e.g. "Realtek\Card Reader Helper"
        }

        /// <summary>
        /// (pure) A cached package that installs into LocalAppDataFolder (one or more folders below it, e.g. Vendor\Product) and has a
        /// custom action that starts wscript, cscript, cmd, PowerShell or mshta, or a script file the package installs itself (a JScript
        /// or VBScript action from an installed file, or a command that names one): its actions and folders, else null. The tables as
        /// the package has them: CustomAction (Action, Type, Source, Target), Directory (Directory, Directory_Parent, DefaultDir),
        /// File (File, FileName).
        /// </summary>
        internal static MsiHit MsiSuspicious(IList<string[]> actions, IList<string[]> dirs, IList<string[]> files)
        {
            var fileNames = files.Where(f => f.Length >= 2).GroupBy(f => f[0]).ToDictionary(g => g.Key, g => MsiLong(g.First()[1]));
            var hit = new MsiHit();
            foreach (var a in actions.Where(a => a.Length >= 4))
            {
                int.TryParse(a[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out var type);
                int kind = type & 0x3F;
                var text = (a[2] + " " + a[3]).Trim();
                bool own = FileRef.Matches(text).Cast<Match>().Any(m => fileNames.TryGetValue(m.Groups[1].Value, out var fn) && ScriptFile.IsMatch(fn))
                           || fileNames.Values.Any(fn => ScriptFile.IsMatch(fn) && text.IndexOf(fn, StringComparison.OrdinalIgnoreCase) >= 0);
                // 21 / 22: JScript / VBScript from a file the package installs (Source = its File key)
                bool scriptFromFile = (kind == 21 || kind == 22) && fileNames.ContainsKey(a[2]);
                if (kind == 35 || !(ScriptHost.IsMatch(text) || own || scriptFromFile)) continue;   // 35 = sets a folder, runs nothing
                var shown = FileRef.Replace(text, m => fileNames.TryGetValue(m.Groups[1].Value, out var fn) ? "[" + fn + "]" : m.Value);
                hit.Actions.Add(a[0] + ": " + Util.Clip(shown));
            }
            if (hit.Actions.Count == 0) return null;
            var parent = dirs.Where(d => d.Length >= 3).GroupBy(d => d[0]).ToDictionary(g => g.Key, g => (Parent: g.First()[1], Name: MsiLong(g.First()[2])));
            var folders = new List<string>();
            foreach (var d in parent.Keys)
            {
                var names = new List<string>();
                var cur = d;
                for (int i = 0; i < 20 && cur != null && cur != "LocalAppDataFolder" && parent.TryGetValue(cur, out var x); i++)
                {
                    if (x.Name != "." && x.Name.Length > 0) names.Insert(0, x.Name);
                    cur = string.IsNullOrEmpty(x.Parent) || x.Parent == cur ? null : x.Parent;
                }
                if (cur == "LocalAppDataFolder" && names.Count > 0) folders.Add(string.Join("\\", names));
            }
            // the deepest folders only (Vendor\Product, not also Vendor)
            hit.Folders = folders.Distinct(Util.IC).Where(f => !folders.Any(o => o.StartsWith(f + "\\", StringComparison.OrdinalIgnoreCase)))
                                 .OrderBy(f => f, Util.IC).Take(5).ToList();
            return hit.Folders.Count > 0 ? hit : null;
        }

        public const string MsiFlag = "!msi-script-action";

        static DateTime? Created(string p) { try { return File.GetCreationTimeUtc(p); } catch { return null; } }

        /// <summary>
        /// Cached Windows Installer packages (C:\Windows\Installer\*.msi, opened read-only) that MsiSuspicious flags. Removal tools delete
        /// these packages, so they may only be there on the first scan. Only flagged packages are listed; all are counted.
        /// </summary>
        void Cached()
        {
            var dir = Path.Combine(c.WinDir, "Installer");
            c.Out.Sub(@"Cached Windows Installer packages (C:\Windows\Installer)",
                "Packages that install into LocalAppData and run a script host, cmd, PowerShell or a script of their own as a custom action.\n" +
                "RenLoader's fake vendor apps start PavinLoader this way. Read only. Time = when Windows cached the package (UTC).");
            string[] msis;
            try { msis = Directory.GetFiles(dir, "*.msi"); }
            catch (Exception e) { c.Err.Add("cached packages: " + e.Message); msis = new string[0]; }
            var t = new Table("@cached", "[kind", "*package", "!status", "name", "version", "publisher", "product code", "<flags");
            int read = 0, failed = 0;
            var flags = new List<string> { MsiFlag };
            foreach (var (path, created) in msis.Select(m => (Path: m, Created: Created(m))).OrderBy(x => x.Created ?? DateTime.MaxValue).ThenBy(x => x.Path, Util.IC))
            {
                List<List<string[]>> tb;
                try
                {
                    tb = Native.MsiTables(path, "SELECT `Property`, `Value` FROM `Property`", "SELECT `Action`, `Type`, `Source`, `Target` FROM `CustomAction`",
                                         "SELECT `Directory`, `Directory_Parent`, `DefaultDir` FROM `Directory`", "SELECT `File`, `FileName` FROM `File`");
                }
                catch (Exception e) { c.Err.Add("cached package " + path + ": " + e.Message); tb = null; }
                if (tb == null) { failed++; continue; }
                read++;
                var hit = MsiSuspicious(tb[1], tb[2], tb[3]);
                if (hit == null) continue;
                var props = tb[0].Where(r => r.Length >= 2).GroupBy(r => r[0]).ToDictionary(g => g.Key, g => g.First()[1]);
                string P(string k) => props.TryGetValue(k, out var v) ? Util.Clip(v) : "";
                var name = P("ProductName"); var ver = P("ProductVersion"); var maker = P("Manufacturer"); var code = P("ProductCode");
                var f = c.F(path);
                t.Add(Log.T(created), "cached msi", f.Path, f.Status, name, ver, maker, code, Rules.FlagCol(flags));
                foreach (var a in hit.Actions) t.More("custom action", a);
                var shownFolders = new List<string>();
                foreach (var rel in hit.Folders)
                {
                    var real = c.Profiles.Select(p => Path.Combine(p.Path, @"AppData\Local", rel)).Where(Directory.Exists).ToList();
                    foreach (var r in real) { var shown = Rules.Fix(c.RealCase(r)) + "\\"; t.More("folder", shown); shownFolders.Add(shown); }
                    if (real.Count == 0) t.More("install folder", @"[LocalAppDataFolder]\" + Rules.Fix(rel) + "\\");
                }
                c.Observe("software", $"{name} | {ver} | {maker}", created, $"{f.Path} ({NameVersion(name, ver)})");
                foreach (var a in hit.Actions) c.Observe("cmd", a, created, f.Path);
                var details = new List<string> { "cached Windows Installer package " + NameVersion(name, ver) + (maker.Length > 0 ? " (" + maker + ")" : "") };
                if (code.Length > 0) details.Add("product code " + code);
                details.Add("custom action " + hit.Actions[0] + (hit.Actions.Count > 1 ? $" (+{hit.Actions.Count - 1} more)" : ""));
                details.Add("installs into " + (shownFolders.Count > 0 ? string.Join(", ", shownFolders) : @"[LocalAppDataFolder]\" + Rules.Fix(hit.Folders[0]) + "\\"));
                c.Find(created, Log.Item(f.Path, f.Status), string.Join("; ", details), flags);
            }
            int listed = t.Count;
            t.WriteTo(c.Out, "no cached package with a script custom action that installs into LocalAppData");
            c.Out.Comment($"Read {Util.Plural(read, "cached package", "cached packages")}, {listed} with a script custom action into LocalAppData" +
                          (failed > 0 ? $"; {failed} could not be opened" : "") + ".");
        }

        /// <summary>(pure) "name version", the version left out when empty or already in the name ("Antigravity 2.32.1", not "... 2.32.1 2.32.1").</summary>
        internal static string NameVersion(string name, string version)
        {
            name = (name ?? "").Trim(); version = (version ?? "").Trim();
            if (version.Length == 0) return name;
            return System.Text.RegularExpressions.Regex.IsMatch(name, @"(^|[^\w.])" + System.Text.RegularExpressions.Regex.Escape(version) + @"($|[^\w.])")
                ? name : (name + " " + version).Trim();
        }

        static DateTime? InstallDate(string s) =>
            DateTime.TryParseExact(s, "yyyyMMdd", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var d) ? d : (DateTime?)null;
    }
}
