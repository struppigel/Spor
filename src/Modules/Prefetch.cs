using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace Spor.Modules
{
    /// <summary>
    /// Prefetch (C:\Windows\Prefetch\*.pf): up to 8 run times per program (timeline: PF), and the "hot" files each program loaded:
    /// executable/script/project/archive types outside trusted locations, Startup, Windows\Temp, other drives, root-level
    /// scheduled task files. Files in known-noise locations are counted only (EXE/BAT/... still shown).
    /// </summary>
    class Prefetch : IModule
    {
        public string Id => "prefetch";
        public string Name => "PREFETCH";
        public string Description => "programs run and the files they loaded";

        const RegexOptions O = Util.RX;
        static readonly Regex Ext = new Regex(@"\.(EXE|DLL|SYS|SCR|COM|CPL|OCX|DRV|BAT|CMD|PS1|PSM1|VBS|VBE|JS|JSC|JSE|WSF|WSH|HTA|LNK|JOB|JAR|MSI|MSP|PIF|SCT|XLL|NODE|CSPROJ|VBPROJ|PROJ|TARGETS|PROPS|SLN|AU3|A3X|AHK|PY|PYW|PYC|PYD|RPA|RPYC?|RPYM|ZIP|RAR|7Z|CAB|ISO|IMG|VHDX?)$", O);
        static readonly Regex Exeish = new Regex(@"\.(EXE|SCR|COM|BAT|CMD|PS1|VBS|VBE|HTA|MSI|MSP|SYS|JOB|PIF)$", O);
        static readonly Regex NoHash = new Regex(@"\.(LNK|JOB)$|\\TASKS\\[^\\]+$", O);   // shortcuts and task files are unique per machine, a hash says nothing
        static readonly Regex Task = new Regex(@"^\\WINDOWS\\(SYSTEM32\\)?TASKS\\[^\\]+$", O);
        static readonly Regex TmpRoot = new Regex(@"^\\(PROGRAMDATA|USERS\\[^\\]+\\APPDATA\\(ROAMING|LOCAL))\\[^\\]+\.TMP$", O);   // .tmp files directly in these folders
        static readonly Regex Installer = new Regex(@"^\\WINDOWS\\INSTALLER\\[^\\]+\.(MSI|MSP)$", O);
        static readonly Regex Inject = new Regex(@"\\DISCORD[^\\]*\\APP-[^\\]+\\MODULES\\DISCORD_DESKTOP_CORE[^\\]*\\(DISCORD_DESKTOP_CORE\\)?INDEX\.JS$", O);   // stealers patch this file
        static readonly Regex LnkNormal = new Regex(@"\\(RECENT|START MENU)\\", O);   // .pdf.lnk in Recent/Start Menu is normal Windows behaviour
        static readonly Regex Vol = new Regex(@"^\\VOLUME\{[0-9a-f]+-([0-9a-f]{8})\}(.*)$", O);
        static readonly Regex VolPrefix = new Regex(@"^\\VOLUME\{[^}]+\}", O);
        const string NoiseList = @"^\\(\$WINREAGENT|\$WINDOWS\.~BT|\$WINDOWS\.~WS)\\|^\\PROGRAMDATA\\(MICROSOFT\\(WINDOWS DEFENDER|WINDOWS\\WER|CLICKTORUN|EDGEUPDATE)|NVIDIA CORPORATION|A-VOLUTE|LENOVO)\\|\\START MENU\\|\\\.M2\\|\\\.VSCODE\\EXTENSIONS\\|\\NODE_MODULES\\|\\SITE-PACKAGES\\|\\APPDATA\\LOCAL\\(PACKAGES|DISCORD|PROGRAMS\\MICROSOFT VS CODE)\\|\\APPDATA\\LOCAL\\MICROSOFT\\EDGE\\USER DATA\\(?!DEFAULT\\EXTENSIONS)|\\APPDATA\\LOCAL\\TEMP\\(MSEDGE_|HSPERFDATA|__PSSCRIPTPOLICYTEST)|\\__PYCACHE__\\|\\PYTHON\d+\\(LIB|DLLS)\\|\\QMLCACHE\\|\\MICROSOFT\\WINDOWS\\RECENT\\";
        // harmless loaded files (whitelist), each with a condition that keeps the attack it could hide visible
        static readonly Regex PsHost = new Regex(@"\\(POWERSHELL|PWSH)\.EXE$", O);
        static readonly Regex PsPolicyTest = new Regex(@"^\\USERS\\[^\\]+\\APPDATA\\LOCAL\\TEMP\\__PSSCRIPTPOLICYTEST_[A-Z0-9]{8}\.[A-Z0-9]{3}\.PS1$", O);
        static readonly Regex DefEngine = new Regex(@"^\\PROGRAMDATA\\MICROSOFT\\WINDOWS DEFENDER\\DEFINITION UPDATES\\\{[0-9A-F-]{36}\}\\MPENGINE\.DLL$", O);
        static readonly Regex DefLoader = new Regex(@"\\(MPSIGSTUB|MSMPENG|MPCMDRUN)\.EXE$", O);
        static readonly Regex MsFolder = new Regex(@"^\\PROGRAMDATA\\MICROSOFT\\(WINDOWS\\APPREPOSITORY\\PACKAGES|VISUALSTUDIO\\SETUP)\\", O);
        static readonly HashSet<string> MsSigners = new HashSet<string>(new[] { "Microsoft Windows", "Microsoft Corporation", "Microsoft Windows Publisher", "Microsoft Windows Software Compatibility Publisher" }, StringComparer.OrdinalIgnoreCase);
        readonly Dictionary<string, int> harmless = new Dictionary<string, int>();
        const int Many = 5;
        static readonly string Self = System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName;   // files used by this many programs are listed once

        Ctx c;
        Regex noise;
        readonly Dictionary<string, string> vol = new Dictionary<string, string>(Util.IC);   // serial -> "C:"
        string sysSerial;

        class Prog
        {
            public string Path, Raw; public bool IsRun, Noisy;
            public List<DateTime> Times = new List<DateTime>();
            public List<string> Files = new List<string>(), Quiet = new List<string>();
            public DateTime Last => Times.Max();
        }

        public void Execute(Ctx ctx)
        {
            c = ctx; noise = Rules.Noise(NoiseList);
            foreach (var d in DriveInfo.GetDrives())
            {
                try { var s = Native.VolumeSerial(d.Name); if (s != null) vol[s] = d.Name.TrimEnd('\\'); } catch { }
            }
            sysSerial = vol.FirstOrDefault(kv => kv.Value.Equals(c.SystemDrive, StringComparison.OrdinalIgnoreCase)).Key;

            var dir = Path.Combine(c.WinDir, "Prefetch");
            string[] pf;
            try { pf = Directory.GetFiles(dir, "*.pf"); }
            catch (Exception e) { c.Out.None("cannot read " + dir + ": " + e.Message); return; }
            if (pf.Length == 0) { c.Out.None("no .pf files in " + dir + " (prefetch disabled, wiped, or no access)"); return; }

            var all = new List<Prog>();
            foreach (var f in pf)
            {
                try { var r = Read(f); if (r != null) all.Add(r); }
                catch (Exception e) { c.Err.Add(Path.GetFileName(f) + ": " + e.Message); }
            }
            // one entry per program path (a program has one .pf per command line / per process, e.g. Electron apps)
            var progs = all.GroupBy(r => r.Path, Util.IC).Select(g => new Prog
            {
                Path = g.First().Path, Raw = g.First().Raw, IsRun = g.Any(r => r.IsRun), Noisy = g.All(r => r.Noisy),
                Times = g.SelectMany(r => r.Times).Distinct().OrderByDescending(t => t).ToList(),
                Files = g.SelectMany(r => r.Files).Distinct(Util.IC).ToList(),
                Quiet = g.SelectMany(r => r.Quiet).Distinct(Util.IC).ToList()
            }).ToList();

            foreach (var p in progs.Where(p => p.IsRun))
                foreach (var t in p.Times) c.Event(t, "PF", p.Path, noHash: p.Raw != null && NoHash.IsMatch(p.Path));

            var recent = progs.Where(p => p.Last >= c.Since).ToList();
            c.Out.Comment($"{pf.Length} .pf files, {progs.Count} programs, {recent.Count} of them run in the last {c.Opt.Days} days (their runs are in the timeline).");

            var cnt = new Dictionary<string, int>(Util.IC);
            foreach (var f in recent.SelectMany(r => r.Files)) cnt[f] = cnt.TryGetValue(f, out var n) ? n + 1 : 1;

            c.Out.Sub("Files loaded by programs run in the last " + c.Opt.Days + " days",
                "Only executables, scripts and archives outside trusted locations. time = program's last run.\n" +
                "loaded: file [status] <==== flags");
            var lt = new Table("@time", "!status", "<flags", "*program");
            foreach (var x in recent.OrderBy(r => r.Last))
            {
                var f = x.Files.Where(s => cnt[s] < Many).ToList();
                if (f.Count == 0) continue;
                if (Util.Folder(x.Path).Equals(Util.Folder(Self), StringComparison.OrdinalIgnoreCase) && Util.Leaf(x.Path).StartsWith("spor", StringComparison.OrdinalIgnoreCase)) continue;   // Spor reads files all over the disk: its own list says nothing
                var pf2 = c.F(x.Path, !NoHash.IsMatch(x.Path));
                lt.Add(Log.T(x.Last), pf2.Status, Rules.FlagCol(Rules.Flags(x.Path)), pf2.Path);
                foreach (var g in f.GroupBy(Util.Folder, Util.IC))
                {
                    var fl = g.Where(Sus).ToList(); var rest = g.Where(s => !Sus(s)).ToList();
                    foreach (var s in fl)
                    {
                        var r = Real(s);
                        lt.More("loaded", c.FF(r, !NoHash.IsMatch(s), Rules.Strong(Rules.Flags(r))));
                        c.Find(x.Last, c.File(r) + Rules.FlagText(Rules.Strong(Rules.Flags(r))) + "  (loaded by " + pf2.Path + ")", "program's last run");
                    }
                    foreach (var s in rest) lt.More("loaded", c.FF(Real(s), !NoHash.IsMatch(s)));   // every file: the paths are needed for removal
                }
            }
            lt.WriteTo(c.Out);
            if (harmless.Count > 0)
                c.Out.Comment($"Hidden: {harmless.Values.Sum()} harmless loaded files (-nowhitelist lists them): " +
                              string.Join(", ", harmless.OrderByDescending(kv => kv.Value).Select(kv => $"{kv.Key} {kv.Value}")));

            var common = cnt.Where(kv => kv.Value >= Many).OrderBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase).ToList();
            if (common.Count > 0)
            {
                c.Out.Sub($"Files loaded by {Many} or more of these programs (listed once)");
                var ct = new Table("programs", "!status", "*file");
                foreach (var kv in common) { var f = c.F(Real(kv.Key), !NoHash.IsMatch(kv.Key)); ct.Add(kv.Value.ToString(), f.Status, f.Path); }
                ct.WriteTo(c.Out);
            }
            var qk = new Dictionary<string, int>(Util.IC);
            foreach (var r in recent)
                foreach (var k in r.Quiet.Select(Key).Distinct(Util.IC)) qk[k] = qk.TryGetValue(k, out var n) ? n + 1 : 1;
            c.Out.Hidden(qk, "programs");
            var np = new Dictionary<string, int>(Util.IC);
            foreach (var r in recent.Where(r => r.Noisy && !r.IsRun)) { var k = Key(r.Raw); np[k] = np.TryGetValue(k, out var n) ? n + 1 : 1; }
            if (np.Count > 0)
            {
                c.Out.Sub("Hidden: programs run from known-noise locations", "Not in the timeline; -nowhitelist lists them.");
                var ht = new Table("=count", "*folder");
                foreach (var kv in np.OrderByDescending(kv => kv.Value).ThenBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)) ht.Add(kv.Value + " programs", kv.Key);
                ht.WriteTo(c.Out);
            }
        }

        static bool Sus(string s) => Rules.Disg.IsMatch(s) || Rules.Dbl.IsMatch(s) || Rules.Bidi.IsMatch(s);

        string Real(string s)
        {
            var m = Vol.Match(s);
            return m.Success && vol.TryGetValue(m.Groups[1].Value, out var d) ? d + m.Groups[2].Value : s;
        }

        string Key(string f)
        {
            var rel = VolPrefix.Replace(f, "");
            var m = noise.Match(rel);
            var k = Real(f.Substring(0, f.Length - rel.Length) + (m.Success ? rel.Substring(0, m.Index + m.Length) : rel));
            return Rules.SxsVersion.Replace(Rules.Fix(c.RealCase(k.TrimEnd('\\')) + (k.EndsWith("\\") ? "\\" : "")), "");
        }

        /// <summary>Flags of a file in a known-noise folder; "x.pdf.lnk" in Recent / Start Menu is a normal shortcut, not a double extension.</summary>
        static List<string> NoiseFlags(string path, string rel)
        {
            var fl = Rules.Flags(path);
            if (rel.EndsWith(".LNK", StringComparison.OrdinalIgnoreCase) && LnkNormal.IsMatch(rel)) fl.Remove("!double-extension");
            return fl;
        }

        /// <summary>2 = show, 1 = count only (known noise), 0 = ignore</summary>
        int Hot(string f, bool program = false, bool check = false)
        {
            var m = Vol.Match(f);
            if (!m.Success) return 0;
            var v = m.Groups[1].Value; var rel = m.Groups[2].Value;
            if (Rules.Bidi.IsMatch(rel) || (Rules.Dbl.IsMatch(rel) && !(rel.EndsWith(".LNK", StringComparison.OrdinalIgnoreCase) && LnkNormal.IsMatch(rel)))) return 2;
            if (Task.IsMatch(rel) || TmpRoot.IsMatch(rel) || Installer.IsMatch(rel)) return 2;
            if (!Ext.IsMatch(rel)) return 0;
            if (Rules.Disg.IsMatch(rel) || Inject.IsMatch(rel)) return 2;
            if (!Rules.Whitelist) return 2;
            if (!v.Equals(sysSerial, StringComparison.OrdinalIgnoreCase) || Rules.Risky.IsMatch(rel)) return 2;
            // known-noise folders (Discord, VS Code, AppData\Local\Programs ...) hide only validly signed files without flags: token stealers
            // and injected modules live there. check: signatures of loaded files only for programs run in the time window
            if (noise.IsMatch(rel))
                return Exeish.IsMatch(rel) || NoiseFlags(Real(f), rel).Count > 0 || ((program || check) && Signature.Applies(rel) && !c.SignedOk(Real(f))) ? 2 : 1;
            if (Rules.Trusted.IsMatch(rel)) return program && !c.SignedOk(Real(f)) ? 2 : 0;   // loaded files: location only (see docs/WHITELISTING.md)
            return 2;
        }

        static string Who(Signature.Result r) => (r.Signer ?? "").Replace(" (catalog)", "").Replace(" (package)", "");

        /// <summary>The program that loaded the files is in a trusted location and validly signed (a copy of explorer.exe elsewhere is not).</summary>
        bool TrustedLoader(string raw) => raw != null && Rules.InTrustedLocation(Real(raw)) && Rules.Strong(Rules.Flags(Real(raw))).Count == 0 && c.SignedOk(Real(raw));

        /// <summary>
        /// A loaded file that is harmless although it is outside trusted locations: returns why (for the hidden count), or null.
        /// Only on the system drive, only files without flags. Each case has a condition that keeps what it could hide visible:
        /// - a shortcut read by a trusted program that is not a LOLBin (the shell for icons and jump lists, Task Manager's startup list, vendor tools):
        ///   only if its target is trusted and its arguments harmless, so a hijacked taskbar or Startup shortcut stays visible
        /// - a DLL in the program's own folder: only if validly signed by the program's signer or by Microsoft, so sideloaded DLLs stay visible
        /// - PowerShell's AppLocker test script __PSScriptPolicyTest_xxxxxxxx.xxx.ps1 in Temp, loaded by powershell.exe or pwsh.exe
        /// - Defender's engine updates (Definition Updates\{GUID}\mpengine.dll, only SYSTEM can write there) loaded by Defender's updater
        /// - Microsoft's own files in ProgramData\Microsoft\Windows\AppRepository\Packages and ProgramData\Microsoft\VisualStudio\Setup: only validly Microsoft-signed
        /// </summary>
        string Harmless(string f, string raw)
        {
            if (!Rules.Whitelist || raw == null) return null;
            var m = Vol.Match(f);
            if (!m.Success || !m.Groups[1].Value.Equals(sysSerial, StringComparison.OrdinalIgnoreCase)) return null;
            var rel = m.Groups[2].Value; var real = Real(f);
            if (Rules.Flags(real).Count > 0 || Inject.IsMatch(rel)) return null;
            try
            {
                if (rel.EndsWith(".LNK", StringComparison.OrdinalIgnoreCase) && !Rules.Lol.IsMatch(raw) && TrustedLoader(raw))
                {
                    var l = File.Exists(real) ? Lnk.Parse(File.ReadAllBytes(real)) : null;
                    if (l?.Target != null && l.Net == null && c.TrustedFile(Environment.ExpandEnvironmentVariables(l.Target))
                        && (string.IsNullOrWhiteSpace(l.Args) || !Rules.ArgsSuspicious(l.Args)))
                        return "shortcuts with a trusted target, read by a trusted program";
                    return null;
                }
                if (PsPolicyTest.IsMatch(rel) && PsHost.IsMatch(raw) && TrustedLoader(raw)) return "PowerShell's AppLocker test scripts";
                if (DefEngine.IsMatch(rel) && DefLoader.IsMatch(raw) && TrustedLoader(raw)) return "Defender engine updates";
                if (MsFolder.IsMatch(rel) && Signature.Applies(real) && File.Exists(real))
                {
                    var s = Signature.Check(real);
                    if (s.Valid && MsSigners.Contains(Who(s))) return "Microsoft-signed files in ProgramData\\Microsoft";
                    return null;
                }
                if (rel.EndsWith(".DLL", StringComparison.OrdinalIgnoreCase) && File.Exists(real)
                    && Util.Folder(real).Equals(Util.Folder(Real(raw)), StringComparison.OrdinalIgnoreCase))
                {
                    var s = Signature.Check(real);
                    if (!s.Valid) return null;
                    var p = Real(raw);
                    var ps = File.Exists(p) ? Signature.Check(p) : null;
                    if (MsSigners.Contains(Who(s)) || (ps != null && ps.Valid && Who(ps).Equals(Who(s), StringComparison.OrdinalIgnoreCase)))
                        return "DLLs in the program's own folder, signed by its publisher or Microsoft";
                }
            }
            catch { }
            return null;
        }

        Prog Read(string path)
        {
            var b = File.ReadAllBytes(path);
            if (b.Length >= 8 && Encoding.ASCII.GetString(b, 0, 3) == "MAM")
                b = Native.DecompressXpressHuff(b, 8, (int)BitConverter.ToUInt32(b, 4));
            if (b.Length < 0x100 || Encoding.ASCII.GetString(b, 4, 4) != "SCCA") throw new Exception("not a prefetch file");
            int ver = BitConverter.ToInt32(b, 0);
            var exe = Encoding.Unicode.GetString(b, 16, 60).Split('\0')[0];
            var times = new List<DateTime>();
            for (int i = 0; i < (ver >= 26 ? 8 : 1); i++)   // Windows 8+: the last 8 run times
            {
                var t = Util.FtTime(BitConverter.ToInt64(b, 128 + 8 * i));
                if (t.HasValue && t.Value.Year > 2000) times.Add(t.Value);
            }
            if (times.Count == 0) return null;
            int off = (int)BitConverter.ToUInt32(b, 100), len = (int)BitConverter.ToUInt32(b, 104);
            if (off < 0 || len < 0 || off + len > b.Length) throw new Exception("bad file name table");
            var files = Encoding.Unicode.GetString(b, off, len).Split(new[] { '\0' }, StringSplitOptions.RemoveEmptyEntries);
            var raw = files.FirstOrDefault(f => f.IndexOf("\\" + exe, StringComparison.OrdinalIgnoreCase) >= 0);
            var r = new Prog { Times = times, Raw = raw, Path = raw != null ? Real(raw) : exe };
            bool recent = times.Max() >= c.Since;   // signature checks only for programs run in the time window
            foreach (var f in files.Distinct(Util.IC))
            {
                if (f == raw) continue;
                int h = Hot(f, false, recent);
                if (h == 2 && recent && Harmless(f, raw) is string why) { harmless[why] = (harmless.TryGetValue(why, out var n) ? n : 0) + 1; continue; }
                if (h == 2) r.Files.Add(f); else if (h == 1) r.Quiet.Add(f);
            }
            // a program in a known-noise folder (VS Code, Discord, ...) is counted, not listed; files it loads still are
            var rr = VolPrefix.Replace(raw ?? "", "");
            r.Noisy = raw != null && Rules.Whitelist && noise.IsMatch(rr) && !Rules.Risky.IsMatch(rr) && Rules.Flags(rr).Count == 0 && !Inject.IsMatch(rr)
                      && recent && c.SignedOk(Real(raw));
            r.IsRun = raw == null || Rules.Lol.IsMatch(raw) || (Hot(raw, recent) == 2 && !r.Noisy);
            return r;
        }
    }
}
