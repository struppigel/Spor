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
        static readonly Regex Vol = new Regex(@"^\\VOLUME\{[0-9a-f]+-([0-9a-f]{8})\}(.*)$", O);
        static readonly Regex VolPrefix = new Regex(@"^\\VOLUME\{[^}]+\}", O);
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
            public string Path, Raw; public bool IsRun, Noisy, Injection;
            public string Exe; public uint? PfHash;   // the name in the .pf header and the path hash in the .pf file name
            public List<DateTime> Times = new List<DateTime>();
            public List<string> Files = new List<string>(), Quiet = new List<string>();
            public DateTime Last => Times.Max();
        }

        public void Execute(Ctx ctx)
        {
            c = ctx; noise = Rules.Noise(Whitelist.Noise("prefetch"));
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
            ResolvePathless(all);
            // one entry per program path (a program has one .pf per command line / per process, e.g. Electron apps)
            // path and raw path from an entry that has its own image (a resolved name-only entry has the upper-case path, no raw one)
            var progs = all.GroupBy(r => r.Path, Util.IC).Select(g => (G: g, F: g.FirstOrDefault(r => r.Raw != null) ?? g.First())).Select(x => new Prog
            {
                Path = x.F.Path, Raw = x.F.Raw, IsRun = x.G.Any(r => r.IsRun), Noisy = x.G.All(r => r.Noisy),
                Times = x.G.SelectMany(r => r.Times).Distinct().OrderByDescending(t => t).ToList(),
                Files = x.G.SelectMany(r => r.Files).Distinct(Util.IC).ToList(),
                Quiet = x.G.SelectMany(r => r.Quiet).Distinct(Util.IC).ToList()
            }).ToList();

            // a Windows accessory that loaded unsigned code from outside Windows and Program Files: malware injected into it
            // (the path and type checks first: dllhost's entries list hundreds of Windows DLLs, signatures only for what passes them)
            foreach (var p in progs.Where(p => Rules.AccessoryHost(p.Path)))
                p.Injection = p.Files.Select(Real).Any(f => Rules.InjectedFile(p.Path, f, false)
                                                           && !(File.Exists(f) && Signature.Applies(f) && c.SignedOk(f)));
            foreach (var p in progs.Where(p => p.Injection)) c.MarkPath(p.Path, Rules.InjectionHostFlag);   // its other lines too (full paths only)

            foreach (var p in progs.Where(p => p.IsRun))
                foreach (var t in p.Times)
                    c.Event(t, "PF", p.Path, noHash: p.Raw != null && NoHash.IsMatch(p.Path), flags: p.Injection ? new List<string> { Rules.InjectionHostFlag } : null);

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
                lt.Add(Log.T(x.Last), pf2.Status, Rules.FlagCol(Rules.Flags(x.Path).Concat(x.Injection ? new[] { Rules.InjectionHostFlag } : new string[0])), pf2.Path);
                // known malware among the loaded files marks the program that loaded them (a dropper, an injected accessory); not a
                // program in Windows / Program Files (an archiver or a scanner reads such files too), except the accessories
                bool relate = Rules.AccessoryHost(x.Path) || (Rules.DrivePath.IsMatch(x.Path) && !Rules.InTrustedLocation(x.Path));
                foreach (var s in f)
                {
                    var r = Real(s);
                    if (!Rules.DrivePath.IsMatch(r)) continue;
                    c.ObserveQuiet(r, x.Last);
                    if (relate) c.Relate(r, x.Path, "loaded " + Util.Leaf(r));
                }
                foreach (var g in f.GroupBy(Util.Folder, Util.IC))
                {
                    var fl = g.Where(Sus).ToList(); var rest = g.Where(s => !Sus(s)).ToList();
                    foreach (var s in fl)
                    {
                        var r = Real(s);
                        lt.More("loaded", c.FF(r, !NoHash.IsMatch(s), Rules.Strong(Rules.Flags(r))));
                        c.Find(x.Last, c.File(r), "loaded by " + pf2.Path, Rules.Strong(Rules.Flags(r)));   // time = the program's last run
                    }
                    foreach (var s in rest)   // every file: the paths are needed for removal
                    {
                        var r = Real(s);
                        lt.More("loaded", c.FF(r, !NoHash.IsMatch(s)), Aggr.On ? LoadedAggr(x.Path, r) : null);
                    }
                }
                // all its loaded files are noise: the program's line goes too (its runs are in the timeline)
                if (x.IsRun && lt.LastMoreAllMarked) lt.Aggr("programs whose loaded files are all hidden");
            }
            lt.WriteTo(c.Out);
            if (harmless.Count > 0)
            {
                // several comment lines, cut between the kinds (a kind's text can contain ", " itself)
                var kinds = harmless.OrderByDescending(kv => kv.Value).Select(kv => $"{kv.Key} {kv.Value}").ToList();
                kinds[0] = $"Hidden: {harmless.Values.Sum()} harmless loaded files (-nowhitelist lists them): " + kinds[0];
                var parts = Log.Chunks(kinds, 190);
                foreach (var part in parts) c.Out.Comment(part);
            }

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
                foreach (var kv in np.OrderByDescending(kv => kv.Value).ThenBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)) ht.Add(Util.Plural(kv.Value, "program", "programs"), kv.Key);
                ht.WriteTo(c.Out);
            }
        }

        static bool Sus(string s) => Rules.Disg.IsMatch(s) || Rules.DoubleExt(s) || Rules.OddChars(s);

        // A program whose prefetch file list lacks its own image (code injected into a suspended calc.exe or charmap.exe) has only
        // its name in the .pf header. The .pf file name holds a hash of the full device path ("\DEVICE\HARDDISKVOLUME3\WINDOWS\
        // SYSTEM32\CALC.EXE"): the Windows folder candidates whose hash matches give the path back. The hash function is not
        // documented and differs between Windows versions, so it is taken from this PC's own .pf files (Calibrate): a function counts
        // only when it gives the file name hash of several programs whose path is known. Without that the entry keeps its bare name.

        /// <summary>(pure) The path hash in a .pf file name ("CALC.EXE-1A2B3C4D.pf" -> 0x1A2B3C4D), null if it has none.</summary>
        internal static uint? PfNameHash(string pfFile)
        {
            var m = Regex.Match(Path.GetFileName(pfFile ?? ""), @"-([0-9A-F]{8})\.pf$", O);
            return m.Success ? Convert.ToUInt32(m.Groups[1].Value, 16) : (uint?)null;
        }

        /// <summary>(pure) Prefetch path hash, Vista and later form: 314159, then *37 + each byte of the UTF-16LE upper-case path.</summary>
        internal static uint HashVista(string devicePath)
        {
            uint h = 314159;
            foreach (var b in Encoding.Unicode.GetBytes((devicePath ?? "").ToUpperInvariant())) h = unchecked(h * 37 + b);
            return h;
        }

        /// <summary>(pure) The same per character instead of per byte.</summary>
        internal static uint HashVistaChars(string devicePath)
        {
            uint h = 314159;
            foreach (var ch in (devicePath ?? "").ToUpperInvariant()) h = unchecked(h * 37 + ch);
            return h;
        }

        /// <summary>(pure) Prefetch path hash, Windows XP form.</summary>
        internal static uint HashXp(string devicePath)
        {
            uint h = 0;
            foreach (var b in Encoding.Unicode.GetBytes((devicePath ?? "").ToUpperInvariant())) h = unchecked(h * 37 + b);
            long v = (long)((ulong)h * 314159269UL % 0x100000000UL);
            if (v > 0x80000000L) v = 0x100000000L - v;
            return (uint)(Math.Abs(v) % 1000000007L);
        }

        internal static readonly Func<string, uint>[] PathHashes = { HashVista, HashVistaChars, HashXp };

        /// <summary>
        /// (pure) The index of the path hash function this PC's .pf files use (PathHashes), from programs with a known device path
        /// and their file name hash: the one that gives the most of them, at least 3 and more than any other; -1 if none does.
        /// </summary>
        internal static int Calibrate(IEnumerable<(string DevicePath, uint Hash)> known)
        {
            var counts = new int[PathHashes.Length];
            foreach (var (dp, h) in known)
                for (int i = 0; i < PathHashes.Length; i++)
                    if (PathHashes[i](dp) == h) counts[i]++;
            int best = Array.IndexOf(counts, counts.Max());
            return counts[best] >= 3 && counts.Where((n, i) => i != best).All(n => n < counts[best]) ? best : -1;
        }

        /// <summary>
        /// (pure) The path of a prefetch entry that has only its program name: the Windows folder (System32, SysWOW64, Windows) whose
        /// device path hashes to the .pf file name's hash; null if none does. deviceRoot: "\Device\HarddiskVolume3", drive: "C:".
        /// </summary>
        internal static string ResolvePath(string exe, uint hash, string deviceRoot, string drive, Func<string, uint> fn)
        {
            if (string.IsNullOrEmpty(exe) || exe.IndexOf('\\') >= 0 || string.IsNullOrEmpty(deviceRoot) || fn == null) return null;
            foreach (var dir in new[] { @"\WINDOWS\SYSTEM32\", @"\WINDOWS\SYSWOW64\", @"\WINDOWS\" })
            {
                var rel = dir + exe.ToUpperInvariant();
                if (fn(deviceRoot.TrimEnd('\\') + rel) == hash) return drive + rel;
            }
            return null;
        }

        /// <summary>Prefetch entries with only a program name get their path back where the .pf file name's hash allows (see above).</summary>
        void ResolvePathless(List<Prog> all)
        {
            if (!all.Any(r => r.Raw == null && r.PfHash.HasValue)) return;
            var root = Native.DosDevice(c.SystemDrive);
            if (root == null || sysSerial == null) return;
            var known = new List<(string, uint)>();
            foreach (var r in all.Where(r => r.Raw != null && r.PfHash.HasValue))
            {
                var m = Vol.Match(r.Raw);
                if (m.Success && m.Groups[1].Value.Equals(sysSerial, StringComparison.OrdinalIgnoreCase)) known.Add((root + m.Groups[2].Value, r.PfHash.Value));
            }
            int fn = Calibrate(known);
            if (fn < 0) return;
            foreach (var r in all.Where(r => r.Raw == null && r.PfHash.HasValue))
                if (ResolvePath(r.Exe, r.PfHash.Value, root, c.SystemDrive, PathHashes[fn]) is string p) r.Path = p;
        }

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
            // a folder ends in "\"; a match that ends inside a name (Temp\__PSSCRIPTPOLICYTEST...) is a name prefix: "*"
            return Rules.SxsVersion.Replace(Rules.Fix(c.RealCase(k.TrimEnd('\\')) + (k.EndsWith("\\") ? "\\" : m.Success ? "*" : "")), "");
        }

        /// <summary>2 = show, 1 = count only (known noise), 0 = ignore</summary>
        int Hot(string f, bool program = false, bool check = false)
        {
            var m = Vol.Match(f);
            if (!m.Success) return 0;
            var v = m.Groups[1].Value; var rel = m.Groups[2].Value;
            if (Rules.OddChars(rel) || Rules.DoubleExt(rel)) return 2;   // x.pdf.lnk in Recent / Start Menu is no double extension
            if (Task.IsMatch(rel) || TmpRoot.IsMatch(rel) || Installer.IsMatch(rel)) return 2;
            if (!Ext.IsMatch(rel)) return 0;
            if (Rules.Disg.IsMatch(rel) || Inject.IsMatch(rel)) return 2;
            if (!Rules.Whitelist) return 2;
            if (!v.Equals(sysSerial, StringComparison.OrdinalIgnoreCase) || Rules.Risky.IsMatch(rel)) return 2;
            // known-noise folders (Discord, VS Code, AppData\Local\Programs ...) hide only validly signed files without flags: token stealers
            // and injected modules live there. check: signatures of loaded files only for programs run in the time window
            if (noise.IsMatch(rel))
                return Exeish.IsMatch(rel) || Rules.Flags(Real(f)).Count > 0 || ((program || check) && Signature.Applies(rel) && !c.SignedOk(Real(f))) ? 2 : 1;
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

        // aggressive whitelist (Aggr): loaded files that are noise on top of Harmless
        static readonly Regex PyEngine = new Regex(@"\.(PY|PYC|PYO|RPY|RPYC|RPYM)$", O);
        static readonly Regex PyEngineFolder = new Regex(@"^\\(RENPY|LIB\\PYTHON[\d.]*)\\", O);
        static readonly Regex RenPyLauncher = new Regex(@"\\LIB\\(PY\d?-)?WINDOWS-[^\\]+$", O);   // Ren'Py's real exe: <game>\lib\py3-windows-x86_64\
        static readonly Regex WinReMount = new Regex(@"^[A-Z]:\\\$WINREAGENT\\SCRATCH\\MOUNT\\", O);
        static readonly Regex WinReLoader = new Regex(@"^[A-Z]:\\WINDOWS\\(SYSTEM32|WINSXS\\[^\\]+)\\(WIMSERV|DISMHOST)\.EXE$", O);
        static readonly Regex Browser = new Regex(@"\\(CHROME|MSEDGE|BRAVE|VIVALDI|OPERA)\.EXE$", O);
        static readonly Regex CrxTemp = new Regex(@"\\APPDATA\\LOCAL\\TEMP\\(CHROMIUMCRX_[^\\]+|SCOPED_DIR[^\\]+\\CRX_INSTALL)\\.*\.JS$", O);
        static readonly Regex PyInstaller = new Regex(@"\\APPDATA\\LOCAL\\TEMP\\_MEI\d+\\", O);
        static readonly Regex AppRootRx = new Regex(@"^[A-Z]:\\(PROGRAM FILES( \(X86\))?|PROGRAMDATA|USERS\\[^\\]+\\APPDATA\\(LOCAL|ROAMING)(\\PROGRAMS)?)\\(MICROSOFT\\)?[^\\]+\\", O);

        /// <summary>
        /// (pure) Which kind of aggressive-whitelist noise a loaded file can be, by its path and the loader's path; LoadedAggr checks
        /// the signatures. "python": Ren'Py / Python engine files in the game's renpy\ or lib\pythonX\ (not site-packages); "winre":
        /// the WinRE image Windows servicing mounts; "crx": a browser unpacking an extension; "unpack": a .NET single-file program's or
        /// a PyInstaller program's own files in Temp; "app": an exe / dll / node in the loader's own app folder.
        /// </summary>
        internal static string LoadedKind(string program, string loaded)
        {
            if (string.IsNullOrEmpty(program) || string.IsNullOrEmpty(loaded) || !Rules.DrivePath.IsMatch(program) || !Rules.DrivePath.IsMatch(loaded)) return null;
            var dir = Util.Folder(program);
            if (RenPyLauncher.IsMatch(dir)) dir = Util.Folder(Util.Folder(dir));
            if (PyEngine.IsMatch(loaded) && !Rules.Interpreter.IsMatch(program) && loaded.StartsWith(dir + "\\", StringComparison.OrdinalIgnoreCase))
            {
                var rest = loaded.Substring(dir.Length);
                if (PyEngineFolder.IsMatch(rest) && rest.IndexOf(@"\SITE-PACKAGES\", StringComparison.OrdinalIgnoreCase) < 0) return "python";
            }
            if (WinReMount.IsMatch(loaded) && WinReLoader.IsMatch(program)) return "winre";
            if (CrxTemp.IsMatch(loaded) && Browser.IsMatch(program)) return "crx";
            var name = Path.GetFileNameWithoutExtension(program);
            if (loaded.IndexOf(@"\APPDATA\LOCAL\TEMP\.NET\" + name + @"\", StringComparison.OrdinalIgnoreCase) >= 0 || PyInstaller.IsMatch(loaded)) return "unpack";
            var root = AppRootRx.Match(program);
            if (root.Success && Regex.IsMatch(loaded, @"\.(EXE|DLL|NODE)$", O) && loaded.StartsWith(root.Value, StringComparison.OrdinalIgnoreCase) && !Inject.IsMatch(loaded)
                && !Aggr.StealerTarget(loaded))
                return "app";
            return null;
        }

        /// <summary>
        /// (pure) A Ren'Py / Python runtime as RenLoader runs it: under a lure name (Setup.exe from the lure folder, in every case
        /// so far) or from a drop location. Its engine files stay listed: they show the lure folder.
        /// </summary>
        internal static bool LureRuntime(string program) => Rules.DropLocation(program) || Names.IsLure(program);

        /// <summary>
        /// Why the aggressive whitelist hides a loaded file (Aggr), or null. Never a flagged file; the loader is validly signed for
        /// "winre", "crx" (by a well-known publisher) and "app" (no drop location, no random-named folder; the loaded file validly
        /// signed too, a deleted one only when an update replaced it). "python" and "unpack" stay listed when the loaded file is
        /// flagged; the program itself is listed by the timeline either way.
        /// </summary>
        string LoadedAggr(string program, string loaded)
        {
            if (Rules.Strong(Rules.Flags(loaded)).Count > 0 || c.MarksOf(loaded).Count > 0) return null;
            bool LoaderOk() => Rules.Strong(Rules.Flags(program)).Count == 0 && !Rules.DropLocation(program) && !Names.RandomFolder(program) && c.SignedOk(program);
            try
            {
                switch (LoadedKind(program, loaded))
                {
                    case "python": return LureRuntime(program) ? null : "Ren'Py / Python engine files of a game";
                    case "unpack": return Names.RandomFolder(program) ? null : ".NET single-file and PyInstaller files unpacked to Temp";
                    case "winre": return c.SignedOk(program) ? "WinRE image mounted by Windows servicing" : null;
                    case "crx": return LoaderOk() && c.ByTrustedSigner(program) ? "browser extensions being unpacked" : null;
                    case "app":
                        return LoaderOk() && Signature.Applies(loaded) && c.SignedOk(loaded) && !Names.RandomFolder(loaded)
                            ? "validly signed files in the program's own app folder" : null;
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
            var r = new Prog { Times = times, Raw = raw, Path = raw != null ? Real(raw) : exe, Exe = exe, PfHash = PfNameHash(path) };
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
