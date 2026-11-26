using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;
using System.Text.RegularExpressions;
using System.Xml;
using Microsoft.Win32;

namespace Spor.Modules
{
    /// <summary>
    /// Autostarts with the time they were created or changed: Run/RunOnce keys (key write time), services (key write time, install
    /// events 7045), scheduled tasks (task file times, Task Scheduler events), Startup folders, WMI event subscriptions.
    /// FRST lists autostarts in full; this puts them on the timeline.
    /// </summary>
    class Persistence : IModule
    {
        public string Id => "persistence";
        public string Name => "PERSISTENCE";
        public string Description => "Run keys, services, scheduled tasks, Startup folders, WMI, with times";

        Ctx c;

        /// <summary>A scheduled task set to hidden (not one of Windows') that runs a program that is not trusted.</summary>
        public const string HiddenTaskFlag = "!hidden-task";

        public void Execute(Ctx ctx)
        {
            c = ctx;
            RunKeys();
            Services();
            Tasks();
            Startup();
            Wmi();
            Hooks();
        }

        // ---------------- Reset and setup hooks ----------------

        static readonly Regex ScriptFile = new Regex(@"\.(cmd|bat|ps1|vbs|js)$", Util.RX);
        static readonly Regex AnswerName = new Regex(@"^(auto)?unattend\.xml$", Util.RX);

        /// <summary>
        /// What Windows runs by itself after "Reset this PC" (C:\Recovery\OEM: ResetConfig.xml and its scripts), at the end of Setup
        /// (Windows\Setup\Scripts) and from answer files (unattend.xml, autounattend.xml in Panther, Sysprep and the root of every
        /// drive): see ResetHooks. !reset-hook when a hook runs code or restores a task or registry values, a task copy or .reg file
        /// waits in C:\Recovery\OEM, or a hook was written in the time window; else the context flag !reset-config. Other files in
        /// C:\Recovery\OEM are listed; a program there that is not validly signed and new is a hook too.
        /// </summary>
        void Hooks()
        {
            var t = new Table("@changed", "[kind", "!status", "<flags", "*file");
            var files = new List<(string Path, string Kind)>();
            var oem = Path.Combine(c.SystemDrive + "\\", @"Recovery\OEM");
            try
            {
                // files directly in the folder first (where a dropped hook waits), then the PC maker's subfolders
                if (Directory.Exists(oem))
                    foreach (var f in Directory.EnumerateFiles(oem).Concat(Directory.EnumerateDirectories(oem).SelectMany(d => SafeFiles(d))).Take(MaxOemFiles))
                        files.Add((f, "recovery"));
            }
            catch (Exception e) { c.Err.Add(oem + ": " + e.Message); }
            int oemFiles = files.Count;
            var setup = Path.Combine(c.WinDir, @"Setup\Scripts");
            try { if (Directory.Exists(setup)) foreach (var f in Directory.EnumerateFiles(setup).Take(50)) files.Add((f, "setup")); }
            catch (Exception e) { c.Err.Add(setup + ": " + e.Message); }
            foreach (var dir in new[] { Path.Combine(c.WinDir, "Panther"), Path.Combine(c.WinDir, @"Panther\Unattend"), Path.Combine(c.WinDir, @"System32\Sysprep") })
                try { if (Directory.Exists(dir)) foreach (var f in Directory.EnumerateFiles(dir, "*.xml").Where(f => AnswerName.IsMatch(Path.GetFileName(f)))) files.Add((f, "answer")); }
                catch (Exception e) { c.Err.Add(dir + ": " + e.Message); }
            // answer files in the root of every drive (Windows Setup reads them there, a USB stick included)
            foreach (var d in DriveInfo.GetDrives())
                try
                {
                    if ((d.DriveType != DriveType.Fixed && d.DriveType != DriveType.Removable) || !d.IsReady) continue;
                    foreach (var f in Directory.EnumerateFiles(d.RootDirectory.FullName, "*.xml").Where(f => AnswerName.IsMatch(Path.GetFileName(f)))) files.Add((f, "answer"));
                }
                catch { }
            // first every file (what it is, what it runs), then the flags: a task copy is evidence when a hook names it
            var recs = new List<HookFile>();
            foreach (var (f, where) in files)
            {
                try { recs.Add(ReadHookFile(f, where, oem)); }
                catch (Exception e) { c.Err.Add(f + ": " + e.Message); }
            }
            var hookCommands = recs.Where(r => r.Script || r.Answer || r.ResetConfig).SelectMany(r => r.Commands).ToList();
            int unlisted = 0;
            DateTime newestUnlisted = DateTime.MinValue;
            foreach (var r in recs)
            {
                var f = r.Path;
                var fi = r.Info;
                try
                {
                    foreach (var cmd in r.Commands) c.Observe("cmd", cmd, fi.LastWriteTimeUtc, $"{r.Kind} {f}: {Rules.Fix(Util.Clip(cmd))}");
                    c.Observe("path", f, fi.LastWriteTimeUtc);
                    bool recent = fi.LastWriteTimeUtc >= c.Since || fi.CreationTimeUtc >= c.Since;

                    bool unsigned = r.Program && !(Signature.Applies(f) && c.SignedOk(f));
                    var outside = recent && r.Hook ? r.Commands.Select(cmd => Cmd.Program(cmd, c.WinDir)).FirstOrDefault(p => RunsOutside(p, oem)) : null;
                    var (fl, reasons, listed) = Judge(r.Hook, r.TaskCopy && NamedBy(fi.Name, hookCommands),
                        r.Reg && r.Where == "recovery" && ResetHooks.RestoresTask(r.Text), r.TooBig, recent, unsigned, outside, r.Commands);
                    if (!listed)
                    {
                        unlisted++;
                        if (fi.LastWriteTimeUtc > newestUnlisted) newestUnlisted = fi.LastWriteTimeUtc;
                        continue;
                    }
                    var st = c.F(f);
                    t.Add(Log.T(fi.LastWriteTimeUtc), r.Kind, st.Status, fl.Count > 0 ? Rules.FlagCol(fl) : "-", st.Path);
                    foreach (var m in r.More) t.More(m.Key, m.Value);
                    if (reasons.Count > 0) t.More("why", string.Join("; ", reasons));
                    c.Event(fi.CreationTimeUtc, "RST", f, $"{r.Kind} created");
                    if ((fi.LastWriteTimeUtc - fi.CreationTimeUtc).TotalMinutes > 2) c.Event(fi.LastWriteTimeUtc, "RST", f, $"{r.Kind} changed");
                    if (fl.Count > 0)
                        c.Find(fi.LastWriteTimeUtc, $"{r.Kind}: {st.Path}" + (st.Status != "-" ? $" [{st.Status}]" : ""),
                               string.Join("; ", reasons), fl, r.More.Where(m => m.Key == "command" || m.Key == "decoded" || m.Key == "script").ToList());
                }
                catch (Exception e) { c.Err.Add(f + ": " + e.Message); }
            }
            var head = "what Windows runs by itself after \"Reset this PC\" (C:\\Recovery\\OEM), at the end of Setup (Setup\\Scripts) and from answer files\n" +
                       "(unattend.xml, autounattend.xml); time = file last changed; phase:/script: = ResetConfig.xml, command: = what a script or answer file runs";
            if (unlisted > 0)
                head += $"\n{unlisted} other files in {oem} not listed: older than the time window, programs validly signed (newest {newestUnlisted:yyyy-MM-dd})";
            if (oemFiles >= MaxOemFiles) head += $"\nonly the first {MaxOemFiles} files of {oem} read";
            // a machine ID kept for after a reinstall (MachineGuid changes; WEEVILPROXY keeps the old one to stay registered with its server)
            try
            {
                using (var k = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography"))
                    if (k?.GetValue("OldMachineGuid") is object old)
                    {
                        var when = Native.LastWrite(k);
                        c.Observe("registry", @"HKLM\SOFTWARE\Microsoft\Cryptography\OldMachineGuid", when);
                        var fl = new List<string> { ResetHooks.HookFlag };
                        t.Add(Log.T(when), "registry", "-", Rules.FlagCol(fl), @"HKLM\SOFTWARE\Microsoft\Cryptography: OldMachineGuid " + Rules.Fix(Convert.ToString(old)));
                        t.More("why", "a machine ID kept for after a reset or reinstall (Windows has no such value)");
                        c.Find(when, @"registry value HKLM\SOFTWARE\Microsoft\Cryptography\OldMachineGuid", "a machine ID kept for after a reset or reinstall", fl);
                    }
            }
            catch (Exception e) { c.Err.Add("OldMachineGuid: " + e.Message); }
            c.Out.Sub("Reset and setup hooks", head);
            t.WriteTo(c.Out, unlisted > 0 ? "none of them" : "none (no C:\\Recovery\\OEM files, setup scripts or answer files)");
        }

        /// <summary>The most files read from C:\Recovery\OEM (a PC maker's factory copy of C: has hundreds).</summary>
        const int MaxOemFiles = 5000;

        /// <summary>The files below a folder; none when it cannot be read (one locked subfolder must not end the walk).</summary>
        static IEnumerable<string> SafeFiles(string dir)
        {
            try { return Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories).ToList(); } catch { return Enumerable.Empty<string>(); }
        }

        /// <summary>A file of the reset and setup hooks: what it is and what it runs.</summary>
        sealed class HookFile
        {
            public string Path, Where, Kind, Text;
            public FileInfo Info;
            public bool ResetConfig, Script, Reg, Answer, Program, TaskCopy, TooBig;
            public bool Hook => ResetConfig || Script || Reg || Answer || TaskCopy;
            public List<string> Commands = new List<string>();
            public List<(string Key, string Value)> More = new List<(string, string)>();
        }

        /// <summary>A task's XML starts with its namespace: a few KB tell whether any file is one.</summary>
        const int TaskSniff = 4096;

        HookFile ReadHookFile(string f, string where, string oem)
        {
            var fi = new FileInfo(f);
            var name = fi.Name;
            var r = new HookFile { Path = f, Where = where, Info = fi };
            r.ResetConfig = name.Equals("ResetConfig.xml", StringComparison.OrdinalIgnoreCase);
            r.Script = ScriptFile.IsMatch(name);
            r.Reg = name.EndsWith(".reg", StringComparison.OrdinalIgnoreCase);
            // Unattend.xml in C:\Recovery\OEM is the answer file "Reset this PC" applies
            r.Answer = AnswerFile(where, name);
            r.Program = Spor.Modules.Files.Exec.IsMatch(name);
            if (r.ResetConfig || r.Script || r.Reg || r.Answer) (r.Text, r.TooBig) = ReadHook(f);
            else if (!r.Program && where == "recovery")
            {
                // any other file may be a task copy (WEEVILPROXY names it after the task, without an extension)
                var sniff = ReadHook(f, TaskSniff).Text;
                if (ResetHooks.IsTaskXml(sniff)) { r.Text = ReadHook(f).Text; r.TaskCopy = !r.ResetConfig && !r.Answer; }
            }
            r.Kind = r.ResetConfig ? "reset config" : r.Answer ? "answer file" : r.TaskCopy ? "task copy" : r.Reg ? "registry file"
                   : r.Script ? (where == "setup" ? "setup script" : "reset script") : r.Program ? "program" : "file";
            if (r.ResetConfig)
                foreach (var (phase, p) in ResetHooks.ResetRuns(r.Text))
                {
                    r.More.Add(("phase", phase));
                    // a path with characters a path cannot have is shown as written (one bad Run must not hide the others)
                    var full = ScriptPath(oem, p);
                    if (full == null) { r.More.Add(("script", Rules.Fix(p))); continue; }
                    bool there = false;
                    try { there = File.Exists(full); } catch { }
                    r.More.Add(("script", Log.Item(Rules.Fix(full), there ? null : "gone")));
                    c.Observe("path", full, fi.LastWriteTimeUtc);
                }
            if (r.Script) r.Commands.AddRange(ResetHooks.Commands(r.Text));
            // a .reg file: its keys (key:); RestoresTask decides, not its value lines (paths of a PC maker's settings)
            if (r.Reg) r.More.AddRange(ResetHooks.RegKeys(r.Text).Take(ResetHooks.MaxCommands).Select(k => ("key", k)));
            if (r.TaskCopy)
            {
                var doc = ResetHooks.Xml(r.Text);
                foreach (System.Xml.XmlNode ex in doc?.GetElementsByTagName("Exec").Cast<System.Xml.XmlNode>() ?? Enumerable.Empty<System.Xml.XmlNode>())
                {
                    var cmd = ex.SelectNodes("*").Cast<System.Xml.XmlNode>().Where(n => n.LocalName == "Command" || n.LocalName == "Arguments").Select(n => n.InnerText.Trim());
                    r.Commands.Add(string.Join(" ", cmd));
                }
            }
            bool autoLogon = false;
            if (r.Answer)
            {
                foreach (var (k, cmd) in ResetHooks.AnswerCommands(r.Text, out autoLogon)) r.Commands.Add(cmd);
                if (File.Exists(Path.Combine(Path.GetPathRoot(f) ?? "", @"sources\boot.wim"))) r.More.Add(("info", @"\sources\boot.wim on this drive: Windows Setup reads this answer file"));
            }
            // the commands that give a reason first: the few shown are the ones that matter
            var shown = ResetHooks.ShowOrder(r.Commands);
            foreach (var cmd in shown.Take(ResetHooks.MaxCommands))
            {
                r.More.Add(("command", Rules.Fix(Cut(Util.Clip(cmd), 200))));
                if (ResetHooks.Decoded(cmd) is string dec) r.More.Add(("decoded", Rules.Fix(dec)));
            }
            if (shown.Count > ResetHooks.MaxCommands) r.More.Add(("info", $"+{shown.Count - ResetHooks.MaxCommands} more commands"));
            if (autoLogon) r.More.Add(("info", "AutoLogon password set (not shown)"));
            if ((fi.Attributes & FileAttributes.Hidden) != 0) r.More.Add(("info", "hidden"));
            return r;
        }

        /// <summary>
        /// (pure) The flags, reasons and whether a file is listed. Evidence (!reset-hook): its commands run code or restore a task or
        /// registry values (ResetHooks.Reasons), a task copy a hook script uses, a .reg file that restores a task, a padded hook, a hook
        /// written in the time window that starts a program outside Windows and Program Files, a new program that is not validly signed.
        /// Context (!reset-config): any other hook written in the time window (a reset or reinstall writes them too). An older hook
        /// with none of these is the PC maker's: listed, no flag. Other files: listed only when new, programs also when not validly
        /// signed (a factory copy of C: holds hundreds of old, signed files).
        /// </summary>
        internal static (List<string> Flags, List<string> Reasons, bool Listed) Judge(bool hook, bool namedTaskCopy, bool regRestores,
            bool tooBig, bool recent, bool unsigned, string outsideProgram, IEnumerable<string> commands)
        {
            var reasons = ResetHooks.Reasons(commands);
            if (namedTaskCopy) reasons.Add("copy of a scheduled task that a reset or setup script uses");
            if (regRestores) reasons.Add("registry file that restores a scheduled task");
            // padded beyond what Spor reads: what follows the part read is unknown
            if (tooBig) reasons.Add($"larger than {ResetHooks.MaxText / 1024 / 1024} MB (padded?): only its start was read");
            if (recent && hook && !string.IsNullOrEmpty(outsideProgram)) reasons.Add("written in the time window; starts " + Rules.Fix(outsideProgram));
            if (recent && unsigned) reasons.Add("new program that is not validly signed");
            var fl = reasons.Count > 0 ? new List<string> { ResetHooks.HookFlag }
                   : recent && hook ? new List<string> { ResetHooks.ConfigFlag } : new List<string>();
            if (recent && hook && reasons.Count == 0) reasons.Add("written in the time window");
            return (fl, reasons, hook || recent || unsigned);
        }

        /// <summary>(pure) A hook command names the file (a task copy the script copies back or registers): its name, at least 4 characters.</summary>
        internal static bool NamedBy(string fileName, IEnumerable<string> commands) =>
            !string.IsNullOrEmpty(fileName) && fileName.Length >= 4 && (commands ?? Enumerable.Empty<string>()).Any(x => x.IndexOf(fileName, StringComparison.OrdinalIgnoreCase) >= 0);

        /// <summary>A program a hook starts that is outside Windows and Program Files and not the PC maker's own in C:\Recovery\OEM.</summary>
        static bool RunsOutside(string program, string oem) =>
            Rules.DrivePath.IsMatch(program ?? "") && !Rules.InTrustedLocation(program)
            && !program.StartsWith(oem + "\\", StringComparison.OrdinalIgnoreCase);

        /// <summary>(pure) An answer file: found where Setup reads them, or an (auto)unattend.xml in C:\Recovery\OEM (the one a reset applies).</summary>
        internal static bool AnswerFile(string where, string name) => where == "answer" || (where == "recovery" && AnswerName.IsMatch(name ?? ""));

        /// <summary>(pure) A ResetConfig.xml Run path as a full path (relative to C:\Recovery\OEM); null when it has characters no path has.</summary>
        internal static string ScriptPath(string oem, string p)
        {
            try { return Path.IsPathRooted(p) ? p : Path.Combine(oem, p); } catch (ArgumentException) { return null; }
        }

        /// <summary>Text cut to n characters with "…".</summary>
        static string Cut(string s, int n) => s == null || s.Length <= n ? s : s.Substring(0, n) + "…";

        /// <summary>The start of a hook file (at most ResetHooks.MaxText bytes) and whether it is bigger ('' when unreadable).</summary>
        static (string Text, bool TooBig) ReadHook(string f, int max = ResetHooks.MaxText)
        {
            try { return ResetHooks.Head(f, max); } catch { return ("", false); }
        }

        /// <summary>
        /// Program of a command: path, flags, [gone]/[unsigned]. Flags of the command: !suspicious for a Windows tool or script interpreter
        /// whose arguments download or run code (irm | iex, a script in ProgramData, -EncodedCommand, Add-MpPreference, ...),
        /// !interpreter-outside for an interpreter where none is installed, !renamed-persisted for a signed decoy in a random folder.
        /// </summary>
        string Show(string cmd, out string prog, out List<string> fl)
        {
            prog = Cmd.Program(cmd, c.WinDir);
            fl = Rules.Flags(prog);
            if (Rules.Lol.IsMatch(prog) && !fl.Contains("!lolbin")) fl.Add("!lolbin");
            var real = c.RealCase(prog);
            if (Names.RenamedDetail(c, real) != null) fl.Add(Names.RenamedFlag);
            if ((Rules.Lol.IsMatch(prog) || Rules.Interpreter.IsMatch(prog)) && Rules.ArgsRunCode(Cmd.Args(cmd))) fl.Add("!suspicious");
            if (Rules.InterpreterOutside(real, c.WinDir, Rules.HasUninstaller))
            {
                fl.Add(Rules.InterpreterOutsideFlag);
                c.MarkPath(real, Rules.InterpreterOutsideFlag);
            }
            if (Names.RenamedPersisted(c, real))
            {
                fl.Add(Names.RenamedPersistedFlag);
                c.MarkPath(real, Names.RenamedPersistedFlag);
            }
            return Rules.DrivePath.IsMatch(prog) ? c.File(prog) : Rules.Fix(prog);
        }

        /// <summary>
        /// A driver outside System32\drivers and the DriverStore gets !outside-driver-folders (in `fl`). True when that flag is all there
        /// is and a well-known publisher signed the driver validly (anti-cheat, VPN): listed, but no SUMMARY line.
        /// </summary>
        bool DriverFlag(string kind, string prog, List<string> fl)
        {
            if (kind != "driver" || !Rules.DrivePath.IsMatch(prog ?? "") || Rules.DriverFolder.IsMatch(prog)) return false;
            if (!fl.Contains("!outside-driver-folders")) fl.Add("!outside-driver-folders");
            // quiet only in an install folder (Program Files, ProgramData), with no other flag (not a vulnerable driver): a signed driver
            // from Temp or any other folder (C:\Only for\CH32\iqvw64.sys) stays a finding
            return Rules.Whitelist && Rules.Strong(fl).All(x => x == "!outside-driver-folders") && Rules.InInstallFolder(prog) && c.ByTrustedSigner(prog);
        }

        /// <summary>Program of a command as (path, status) for a table.</summary>
        (string Path, string Status) ProgF(string cmd, out string prog, out List<string> fl)
        {
            Show(cmd, out prog, out fl);
            return Rules.DrivePath.IsMatch(prog) ? c.F(prog) : (Rules.Fix(prog), "-");
        }

        /// <summary>
        /// "module:" sub-line values for the unsigned DLLs a persisted program side-loads (Sideload), with their timeline lines.
        /// Side-loading hosts are often persisted from AppData or ProgramData.
        /// </summary>
        List<string> Modules(string prog)
        {
            var hits = Sideload.For(c, prog);
            foreach (var h in hits) Sideload.Events(c, h);
            return hits.Select(h => Sideload.ModuleLine(c, h)).ToList();
        }

        /// <summary>Trusted program (location + valid signature, see Ctx.TrustedFile) with harmless arguments.</summary>
        bool Trusted(string prog, string args = null) => (c.TrustedFile(prog) && !Rules.ArgsSuspicious(args)) || LolOk(prog, args);

        /// <summary>
        /// A LOLBin in a service or task is fine only when what it runs is fine: signed and in System32/SysWOW64, and
        /// rundll32: the DLL is trusted (location + valid signature), cmd: it runs one trusted .cmd/.bat, others: switches only (msiexec /V).
        /// </summary>
        bool LolOk(string prog, string args)
        {
            var m = Rules.DrivePath.Match(prog ?? "");
            if (!m.Success || !Rules.Lol.IsMatch(prog) || !Regex.IsMatch(m.Groups[2].Value, @"^\\WINDOWS\\(SYSTEM32|SYSWOW64)\\[^\\]+$", Util.RX) || !c.SignedOk(prog)) return false;
            args = (args ?? "").Trim();
            var name = Path.GetFileNameWithoutExtension(prog).ToLowerInvariant();
            string Full(string f)
            {
                f = Environment.ExpandEnvironmentVariables(f.Trim().Trim('"'));
                return f.Contains("\\") ? f : Path.Combine(c.WinDir, "System32", f);
            }
            if (name == "rundll32")
            {
                var a = Regex.Replace(args, @"^(/d\s+)", "", RegexOptions.IgnoreCase);
                int comma = a.IndexOf(',');
                if (comma <= 0) return false;
                var dll = Full(a.Substring(0, comma));
                return c.TrustedFile(dll) && !Rules.ArgsSuspicious(a.Substring(comma + 1));
            }
            if (name == "cmd")
            {
                var rest = Regex.Replace(args, @"^((/[a-z]\s+)*)", "", RegexOptions.IgnoreCase).Trim();
                if (!Regex.IsMatch(rest, @"^""?[^""&|<>^]+\.(cmd|bat)""?$", Util.RX)) return false;
                var script = Full(rest);
                return Rules.InTrustedLocation(script) && File.Exists(script);
            }
            return args.Length == 0 || args.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries).All(t => Regex.IsMatch(t, @"^[-/][\w:-]*$"));
        }
        static readonly Regex BrowserExe = new Regex(@"\\(CHROME|MSEDGE|BRAVE|VIVALDI|OPERA|FIREFOX)\.EXE$", Util.RX);

        /// <summary>
        /// Aggressive whitelist (Aggr): a program a Run value, task or Startup item starts that needs no line of its own: on disk, no
        /// flags, no side-loaded module, harmless arguments, not a browser (analysts delete Edge's AutoLaunch values), and either
        /// trusted (Windows / Program Files, valid signature, not a LOLBin or interpreter) or a per-user app with its own signer
        /// (Aggr.Pair: OneDrive, Zoom, ...).
        /// </summary>
        bool AggrProgram(string prog, string args, List<string> fl, int modules)
        {
            if (string.IsNullOrEmpty(prog) || !Rules.DrivePath.IsMatch(prog) || (fl != null && fl.Count > 0) || modules > 0) return false;
            if (BrowserExe.IsMatch(prog) || Aggr.StealerTarget(prog) || Rules.ArgsSuspicious(args)) return false;
            try
            {
                var real = c.RealCase(prog);
                if (!File.Exists(real)) return false;
                return c.TrustedFile(real) || Aggr.Pair(real);
            }
            catch { return false; }
        }

        const string AggrTrusted = "entries that start a validly signed program in Windows / Program Files or a known per-user app";

        readonly HashSet<string> hiddenTasks = new HashSet<string>(Util.IC);
        readonly Dictionary<string, int> publisherTasks = new Dictionary<string, int>(Util.IC);
        int staleTasks, lockedTasks;

        /// <summary>Windows tasks whose program feature updates remove (24H2+), with that program in System32.</summary>
        static Dictionary<string, string> StaleTasks => Whitelist.StaleTasks;   // resources/whitelist.txt, scope "stale-task"

        /// <summary>Windows tasks only SYSTEM can read: access denied there is normal for an admin.</summary>
        static HashSet<string> LockedTasks => Whitelist.LockedTasks;   // resources/whitelist.txt, scope "locked-task"

        /// <summary>
        /// The well-known publisher (resources/publishers.txt) whose validly signed programs every action runs, or null. The program is in
        /// Windows / Program Files, or in ProgramData (vendor folders like ProgramData\Lenovo, outside Windows and Program Files: then
        /// also no side-loaded DLL next to it); its arguments are harmless; no flags; actions of several publishers: null.
        /// </summary>
        string PublisherTask(List<(string Prog, string Args, List<string> Fl)> acts)
        {
            string who = null;
            foreach (var (prog, args, fl) in acts)
            {
                if (string.IsNullOrEmpty(prog) || !Rules.DrivePath.IsMatch(prog) || fl.Count > 0 || Rules.ArgsSuspicious(args)) return null;
                var inProgramData = prog.StartsWith(Path.Combine(c.SystemDrive + "\\", "ProgramData") + "\\", StringComparison.OrdinalIgnoreCase);
                if (!Rules.InTrustedLocation(prog) && !(inProgramData && Sideload.For(c, prog).Count == 0)) return null;
                if (!c.SignedOk(prog)) return null;
                var s = (Signature.Check(prog).Signer ?? "").Replace(" (catalog)", "");
                if (!Rules.TrustedSigners.Contains(s) || (who != null && !who.Equals(s, StringComparison.OrdinalIgnoreCase))) return null;
                who = s;
            }
            return who;
        }

        void RunKeys()
        {
            c.Out.Sub("Run keys (all entries)", "time = when the key was last changed (Windows stores no time per entry)\n" +
                      "program: = what the entry starts (with its status), arguments: = its arguments, value: = the value name when it has a backslash");
            var rt = new Table("@time", "[kind", "<flags", "*entry");
            var keys = new List<(string Name, RegistryKey Root, string Path)>();
            foreach (var sub in new[] { @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                                        @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
                                        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run" })
                keys.Add(("HKLM\\" + sub, Registry.LocalMachine, sub));
            foreach (var h in c.Hives)
                foreach (var sub in new[] { @"Software\Microsoft\Windows\CurrentVersion\Run", @"Software\Microsoft\Windows\CurrentVersion\RunOnce",
                                            @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run" })
                    keys.Add(("HKU\\" + h.User + "\\" + sub, h.Root, sub));
            bool any = false;
            foreach (var k in keys)
            {
                try
                {
                    using (var key = k.Root.OpenSubKey(k.Path))
                    {
                        if (key == null) continue;
                        var names = key.GetValueNames();
                        if (names.Length == 0) continue;
                        var t = Native.LastWrite(key);
                        any = true;
                        var kind = k.Path.EndsWith(@"Policies\Explorer\Run", StringComparison.OrdinalIgnoreCase) ? "policy-run"
                                 : k.Path.EndsWith("RunOnce", StringComparison.OrdinalIgnoreCase) ? "runonce" : "run";
                        var progs = new List<string>();
                        var same = new Dictionary<string, (int Row, List<string> Names)>(StringComparer.OrdinalIgnoreCase);   // aggressive: one line per command
                        foreach (var n in names)
                        {
                            var cmd = Convert.ToString(key.GetValue(n)) ?? "";
                            var pf = ProgF(cmd, out var prog, out var fl);
                            var runItem = $"Run entry {Rules.Fix(n)} = {Log.Item(pf.Path, pf.Status)}";
                            c.Observe("run", n, t, runItem); c.Observe("cmd", cmd, t, runItem);
                            if (Rules.DrivePath.IsMatch(prog ?? "")) c.Observe("path", prog, t);
                            progs.Add(n);
                            // the entry on the line, what it starts below; the value name only when it has a backslash (then it cannot be cut
                            // from the entry reliably), else it is the entry's last part
                            rt.Add(Log.T(t), kind, Rules.FlagCol(fl), k.Name + "\\" + Rules.Fix(n));
                            rt.More("program", Log.Item(pf.Path, pf.Status));
                            rt.More("arguments", Rules.Fix(Cmd.Args(cmd)));
                            if (n.Contains("\\")) rt.More("value", Rules.Fix(n));
                            var mods = Modules(prog);
                            foreach (var m in mods) rt.More("module", m);
                            if (Aggr.On)
                            {
                                var norm = Regex.Replace(cmd.Trim(), @"\s+", " ");
                                if (same.TryGetValue(norm, out var first))
                                {
                                    rt.Aggr(Aggr.Dup("Run values that start the same command as a value listed in the same key"));
                                    if (rt.LastMarked) first.Names.Add(Rules.Fix(n));   // a flagged repeat stays listed itself
                                }
                                else
                                {
                                    same[norm] = (rt.Count - 1, new List<string>());
                                    if (AggrProgram(prog, Cmd.Args(cmd), fl, mods.Count)) rt.Aggr(AggrTrusted);
                                }
                            }
                            if (Rules.Strong(fl).Count > 0) c.Find(t, $"Run entry {Rules.Fix(n)} = {c.File(prog)}", null, fl);   // time = key changed
                        }
                        // aggressive: the values a hidden same-command line had, on the line that stays (fixlists delete each value by name)
                        if (Aggr.Hide)
                            foreach (var kv in same.Values.Where(v => v.Names.Count > 0))
                                foreach (var chunk in Log.Chunks(kv.Names)) rt.MoreAt(kv.Row, "same command", chunk);
                        // the values it has now on now: sub-lines (a Run key can have dozens)
                        c.Event(t, "AUT", null, text: $"{k.Name} changed ({progs.Count} values now)", more: Log.Chunks(progs).Select(p => ("now", p)).ToList());
                    }
                }
                catch (Exception e) { c.Err.Add(k.Name + ": " + e.Message); }
            }
            rt.WriteTo(c.Out);
        }

        void Services()
        {
            c.Out.Sub(Rules.Whitelist ? "Services and drivers outside trusted locations" : "Services and drivers", "time = when the service key was last changed");
            var sv = new List<(DateTime? T, string[] F, List<(string Key, string Value)> More)>();
            try
            {
                using (var svc = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services"))
                    foreach (var n in svc.GetSubKeyNames())
                        using (var k = svc.OpenSubKey(n))
                        {
                            if (k == null) continue;
                            var ip = Convert.ToString(k.GetValue("ImagePath")) ?? "";
                            if (ip.Length == 0) continue;
                            string dll = null;
                            using (var p = k.OpenSubKey("Parameters")) dll = Convert.ToString(p?.GetValue("ServiceDll"));
                            var cmd = !string.IsNullOrEmpty(dll) && Regex.IsMatch(ip, @"svchost\.exe", Util.RX) ? dll : ip;
                            var pf = ProgF(cmd, out var prog, out var fl);
                            var disp = Log.Item(pf.Path, pf.Status);
                            // Autodetect sees every service, also the ones the whitelist hides (malware dressed as a Windows service)
                            var t = Native.LastWrite(k);
                            var svItem = $"service {Rules.Fix(n)}: {disp}";
                            c.Observe("service", n, t, svItem); c.Observe("cmd", ip, t, svItem);
                            if (Rules.DrivePath.IsMatch(prog ?? "")) c.Observe("path", prog, t);
                            if (Rules.Whitelist && Trusted(prog, cmd == dll ? null : Cmd.Args(ip)) && Rules.Strong(fl).Count == 0) continue;
                            var start = Convert.ToInt32(k.GetValue("Start") ?? -1);
                            var st = start == 0 ? "boot" : start == 1 ? "system" : start == 2 ? "auto" : start == 3 ? "manual" : start == 4 ? "disabled" : "?";
                            var type = Convert.ToInt32(k.GetValue("Type") ?? 0);
                            var kind = (type & 0xF) != 0 ? "driver" : "service";   // 1 kernel driver, 2 file system driver, 8 recognizer; 0x10/0x20 services
                            bool quietDriver = DriverFlag(kind, prog, fl);
                            // before the row is written: the table and the SUMMARY show the same flags
                            bool unsignedAuto = !Trusted(prog) && start <= 2 && Ctx.BadSig(pf.Status);
                            if (unsignedAuto && !fl.Contains("!unsigned")) fl.Add("!unsigned");
                            // svchost-hosted: the DLL is what FRST lists and links; sub-line with its status (it is in FILES through ProgF)
                            var dllLine = cmd == dll ? Log.Item(pf.Path, pf.Status, null, Rules.FlagCol(fl)) : null;
                            var svMore = new List<(string Key, string Value)>();
                            if (dllLine != null) svMore.Add(("dll", dllLine));
                            foreach (var m in Modules(prog)) svMore.Add(("module", m));
                            sv.Add((t, new[] { Log.T(t), kind, st, pf.Status, Rules.FlagCol(fl), Rules.Fix(n), pf.Path + (dll != null && cmd == dll ? " (svchost DLL)" : "") }, svMore));
                            if (Rules.DrivePath.IsMatch(prog)) c.Event(t, "SVC", prog, $"service {n} ({st}) changed");
                            else c.Event(t, "SVC", null, text: $"service {n} ({st}) changed: {Util.Clip(Rules.Fix(ip), 120)}");
                            if ((Rules.Strong(fl).Count > 0 && !quietDriver) || unsignedAuto) c.Find(t, $"service {Rules.Fix(n)} ({st}): {disp}", null, fl);   // time = key changed
                        }
            }
            catch (Exception e) { c.Err.Add("Services: " + e.Message); }
            var svt = new Table("@time", "[kind", "start", "!status", "<flags", "*service", ">program");
            foreach (var r in sv.OrderBy(r => r.T)) { svt.Add(r.F); foreach (var m in r.More) svt.More(m.Key, m.Value); }
            svt.WriteTo(c.Out);

            var ev = Ev.Query("System", "EventID=7045", c.Since, 2000, c.Err);
            ev.Reverse();   // the newest are read (up to the limit), listed oldest first
            c.Out.Sub("Services installed in the last " + c.Opt.Days + " days (System event 7045)" + (Rules.Whitelist ? ", except signed programs in trusted locations" : ""));
            var it = new Table("@time", "[kind", "account", "!status", "<flags", "*service", ">program");
            var installs = new Dictionary<string, (int Row, int More, DateTime? Last)>(StringComparer.OrdinalIgnoreCase);   // aggressive: repeats
            foreach (var e in ev)
            {
                var t = e.TimeCreated?.ToUniversalTime();
                var name = Ev.P(e, 0); var ip = Ev.P(e, 1); var acct = Ev.P(e, 4);
                var kind = Regex.IsMatch(Ev.P(e, 2) ?? "", "driver", Util.RX) ? "driver" : "service";
                var pf = ProgF(ip, out var prog, out var fl);
                var disp = Log.Item(pf.Path, pf.Status);
                var instItem = $"service installed: {Rules.Fix(name)}: {disp}";
                c.Observe("service", name, t, instItem); c.Observe("cmd", ip, t, instItem);
                if (Rules.DrivePath.IsMatch(prog ?? "")) c.Observe("path", prog, t);
                // svchost-hosted: the event has no DLL; the service key (if it is still there) has it, and the DLL decides
                string dllLine = null; string dprog = null; List<string> dfl = null;
                if (Regex.IsMatch(prog ?? "", @"\\svchost\.exe$", Util.RX) && SvcDll(name) is string dll)
                {
                    var df = ProgF(dll, out dprog, out dfl);
                    dllLine = Log.Item(df.Path, df.Status, null, Rules.FlagCol(dfl));
                }
                bool trusted = dprog != null ? Trusted(dprog) && Rules.Strong(dfl).Count == 0 : Trusted(prog, Cmd.Args(ip));
                if (Rules.Whitelist && trusted && Rules.Strong(fl).Count == 0) { e.Dispose(); continue; }
                bool quietDriver = DriverFlag(kind, prog, fl);
                it.Add(Log.T(t), kind, acct, pf.Status, Rules.FlagCol(fl), Rules.Fix(name), pf.Path);
                if (Aggr.On)
                {
                    var key = string.Join("|", kind, acct, pf.Status, Rules.FlagCol(fl), name, pf.Path, ip);
                    if (installs.TryGetValue(key, out var firstInstall))
                    {
                        it.Aggr(Aggr.Dup("repeated installs of the same service (the first one is listed)"));
                        if (it.LastMarked) installs[key] = (firstInstall.Row, firstInstall.More + 1, t);   // a flagged repeat stays listed itself
                    }
                    else installs[key] = (it.Count - 1, 0, t);
                }
                it.More("dll", dllLine);
                // what the service runs, when the program is not all of it (cmd.exe /c ..., a script host and its script)
                var ipArgs = Cmd.Args(ip);
                if (ipArgs.Length > 0) it.More("arguments", Rules.Fix(ipArgs));
                foreach (var m in Modules(prog)) it.More("module", m);
                if (Rules.DrivePath.IsMatch(prog)) c.Event(t, "SVC", prog, $"service {name} installed");
                else c.Event(t, "SVC", null, text: $"service {name} installed: {Util.Clip(Rules.Fix(ip), 120)}", flags: fl);
                // a SUMMARY line only with a reason: a strong flag or a signature that does not hold ([gone] alone is none: a security
                // product reinstalling its drivers again and again)
                bool badSig = Ctx.BadSig(pf.Status) || (dllLine != null && Ctx.BadSig(dllLine));
                if (!trusted && badSig && !fl.Contains("!unsigned")) fl.Add("!unsigned");
                // evidence (a strong flag, a signature that does not hold) or, else, context: a service the whitelist does not hide was
                // installed (a security product reinstalling its drivers is one line with "+N more times" in the SUMMARY)
                // a well-known publisher's driver in its install folder (quietDriver): context only, without !outside-driver-folders
                var baseFl = quietDriver ? fl.Where(x => x != "!outside-driver-folders").ToList() : fl;
                var sumFl = (Rules.Strong(baseFl).Count > 0) || (!trusted && badSig) ? baseFl : baseFl.Concat(new[] { "!new-service" }).ToList();
                c.Find(t, $"service installed: {Rules.Fix(name)}: {disp}" + (dllLine != null ? ", dll " + dllLine : ""), null, sumFl);
                e.Dispose();
            }
            if (Aggr.Hide)
                foreach (var r in installs.Values.Where(r => r.More > 0))
                    it.MoreAt(r.Row, "installed again", $"+{r.More} more times, last {Log.T(r.Last)}");
            it.WriteTo(c.Out);
        }

        /// <summary>ServiceDll of a service (Parameters key, else the service key), or null.</summary>
        static string SvcDll(string name)
        {
            if (string.IsNullOrEmpty(name)) return null;
            try
            {
                using (var k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\" + name))
                {
                    if (k == null) return null;
                    using (var p = k.OpenSubKey("Parameters"))
                    {
                        var d = Convert.ToString(p?.GetValue("ServiceDll") ?? k.GetValue("ServiceDll"));
                        return string.IsNullOrEmpty(d) ? null : d;
                    }
                }
            }
            catch { return null; }
        }

        void Tasks()
        {
            var root = Path.Combine(c.WinDir, @"System32\Tasks");
            c.Out.Sub(Rules.Whitelist ? "Scheduled tasks, except Microsoft tasks that run trusted programs" : "Scheduled tasks",
                "created / changed = task file times; program: / arguments: = the task's first action, action: = further actions; info: hidden, author");
            var tt = new Table("@created", "[kind", "changed", "<flags", "*task");
            var trows = new List<(DateTime T, string[] F, List<string> More, string Aggr)>();
            IEnumerable<string> files;
            try { files = Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories).ToList(); }
            catch (Exception e) { c.Out.None("cannot read " + root + ": " + e.Message); return; }
            foreach (var f in files)
            {
                try
                {
                    var name = f.Substring(root.Length);
                    var fi = new FileInfo(f);
                    var x = new XmlDocument(); x.LoadXml(Util.ReadText(f));
                    var ns = new XmlNamespaceManager(x.NameTable); ns.AddNamespace("t", "http://schemas.microsoft.com/windows/2004/02/mit/task");
                    var acts = new List<(string Prog, string Line, List<string> Fl, string Path, string Status, string Args)>();
                    foreach (XmlNode ex in x.SelectNodes("//t:Actions/t:Exec", ns))
                    {
                        var cmd = ex.SelectSingleNode("t:Command", ns)?.InnerText ?? "";
                        var args = ex.SelectSingleNode("t:Arguments", ns)?.InnerText ?? "";
                        var pf = ProgF(cmd, out var prog, out var fl);
                        // the task's arguments are not part of its command: what they run is checked here
                        if ((Rules.Lol.IsMatch(prog) || Rules.Interpreter.IsMatch(prog)) && Rules.ArgsRunCode(args) && !fl.Contains("!suspicious")) fl.Add("!suspicious");
                        var disp = Log.Item(pf.Path, pf.Status);
                        acts.Add((prog, disp + (args.Length > 0 ? "  " + Rules.Fix(args) : ""), fl, pf.Path, pf.Status, Rules.Fix(args)));
                    }
                    foreach (XmlNode ch in x.SelectNodes("//t:Actions/t:ComHandler/t:ClassId", ns))
                    {
                        // COM handler: the DLL comes from the registry; a per-user CLSID entry overrides the machine one (COM hijacking)
                        var (dll, where) = ComServer(ch.InnerText);
                        if (dll == null) { acts.Add(("", "COM handler " + ch.InnerText, new List<string>(), "COM handler " + ch.InnerText + " (not registered)", "-", "")); continue; }
                        var pf = ProgF(dll, out var prog, out var fl);
                        if (where != "HKLM") fl.Add("!com-hijack");
                        acts.Add((prog, Log.Item(pf.Path, pf.Status) + " (COM handler " + ch.InnerText + ", " + where + ")", fl, pf.Path + " (COM handler, " + where + ")", pf.Status, ""));
                    }
                    // Autodetect sees every task, also the ones the whitelist hides
                    var taskItem = $"task {Rules.Fix(name)}: {(acts.Count > 0 ? acts[0].Line : "(no action)")}";
                    c.Observe("task", name, fi.CreationTimeUtc, taskItem);
                    foreach (var a in acts)
                    {
                        if (Rules.DrivePath.IsMatch(a.Prog)) c.Observe("path", a.Prog, fi.CreationTimeUtc);
                        c.Observe("cmd", (a.Prog + " " + a.Args).Trim(), fi.CreationTimeUtc, taskItem);
                    }
                    bool ms = name.StartsWith(@"\Microsoft\", StringComparison.OrdinalIgnoreCase);
                    // hidden only if every action runs a trusted program (location + valid signature, not a LOLBin) with harmless arguments;
                    // older than the time window: any task name, else only \Microsoft\ tasks
                    // an unregistered COM handler runs nothing (a per-user registration would have been found first)
                    bool Unregistered((string Prog, string Line, List<string> Fl, string Path, string Status, string Args) a) => a.Prog.Length == 0 && a.Path.EndsWith("(not registered)");
                    bool allTrusted = acts.Count > 0 && acts.All(a => Unregistered(a)
                                                                     || (a.Prog.Length > 0 && Trusted(a.Prog, a.Args) && Rules.Strong(a.Fl).Count == 0 && !a.Fl.Contains("!com-hijack")));
                    if (Rules.Whitelist && allTrusted && (ms || fi.CreationTimeUtc < c.Since || acts.All(Unregistered))) { hiddenTasks.Add(name); continue; }
                    // Windows' own tasks whose program a feature update removed (normal on 24H2 and later): by exact name and program
                    if (Rules.Whitelist && StaleTasks.TryGetValue(name, out var staleExe) && acts.Count == 1
                        && acts[0].Prog.Equals(Path.Combine(c.WinDir, "System32", staleExe), StringComparison.OrdinalIgnoreCase) && !File.Exists(acts[0].Prog))
                    { hiddenTasks.Add(name); staleTasks++; continue; }
                    // tasks of well-known publishers (Lenovo, Google's updater, ...): every action a program validly signed by one, in
                    // Windows / Program Files or the publisher's ProgramData folder, with harmless arguments and no side-loaded DLL
                    if (Rules.Whitelist && acts.Count > 0 && PublisherTask(acts.Select(a => (a.Prog, a.Args, a.Fl)).ToList()) is string pub)
                    { hiddenTasks.Add(name); publisherTasks[pub] = (publisherTasks.TryGetValue(pub, out var pn) ? pn : 0) + 1; continue; }
                    var author = Native.IndirectString(x.SelectSingleNode("//t:RegistrationInfo/t:Author", ns)?.InnerText);   // a resource reference ("$(@...usosvc.dll,-103)") as its text
                    var hidden = x.SelectSingleNode("//t:Settings/t:Hidden", ns)?.InnerText == "true";
                    var first = acts.FirstOrDefault();
                    var changed = (fi.LastWriteTimeUtc - fi.CreationTimeUtc).TotalMinutes > 2;
                    // the first action on program: / arguments: lines (the line itself would get too long)
                    var more = new List<string> { "program: " + Log.Item(first.Path ?? "(no action)", first.Status) };
                    if (!string.IsNullOrEmpty(first.Args)) more.Add("arguments: " + first.Args);
                    more.AddRange(acts.Skip(1).Select(a => "action: " + Log.Item(a.Path, a.Status, a.Args.Length > 0 ? "arguments " + a.Args : null, Rules.FlagCol(a.Fl))));
                    var info = string.Join(", ", new[] { hidden ? "hidden" : null, string.IsNullOrEmpty(author) ? null : "author " + author }.Where(v => v != null));
                    if (info.Length > 0) more.Add("info: " + info);
                    foreach (var a in acts) more.AddRange(Modules(a.Prog).Select(m => "module: " + m));
                    // the task's flags: those of every action (a second action can be the one that downloads code); a program that is
                    // not trusted and not validly signed: !unsigned; a hidden task (not Windows') that runs one not trusted: !hidden-task
                    var taskFl = acts.SelectMany(a => a.Fl).Distinct().ToList();
                    if (acts.Any(a => a.Prog.Length > 0 && !Trusted(a.Prog) && Ctx.BadSig(a.Line)) && !taskFl.Contains("!unsigned")) taskFl.Add("!unsigned");
                    if (hidden && !ms && acts.Any(a => a.Prog.Length > 0 && !Trusted(a.Prog)) && !taskFl.Contains(HiddenTaskFlag)) taskFl.Add(HiddenTaskFlag);
                    var strongFl = Rules.Strong(taskFl);
                    // aggressive: a task (not hidden) whose every action starts a trusted program or a per-user app (updaters: OneDrive, Zoom, ...)
                    string taskAggr = Aggr.On && !hidden && acts.Count > 0 && taskFl.Count == 0 && !more.Any(m => m.StartsWith("module: ", StringComparison.Ordinal))
                                      && acts.All(a => AggrProgram(a.Prog, a.Args, a.Fl, 0)) ? AggrTrusted : null;
                    trows.Add((fi.CreationTimeUtc, new[] { Log.T(fi.CreationTimeUtc), "task", changed ? Log.T(fi.LastWriteTimeUtc) : "-", Rules.FlagCol(taskFl),
                                                           Rules.Fix(name) }, more, taskAggr));
                    // the events without the task's flags: its SUMMARY line is the finding below (one line, not two)
                    if (first.Prog != null && Rules.DrivePath.IsMatch(first.Prog))
                    {
                        c.Event(fi.CreationTimeUtc, "TSK", first.Prog, $"task {name} created");
                        if (changed) c.Event(fi.LastWriteTimeUtc, "TSK", first.Prog, $"task {name} changed");
                    }
                    else
                    {
                        c.Event(fi.CreationTimeUtc, "TSK", null, text: $"task {Rules.Fix(name)} created: {Util.Clip(first.Line ?? "", 120)}");
                        if (changed) c.Event(fi.LastWriteTimeUtc, "TSK", null, text: $"task {Rules.Fix(name)} changed");
                    }
                    if (strongFl.Count > 0 || acts.Any(a => a.Prog.Length > 0 && !Trusted(a.Prog) && Ctx.BadSig(a.Line)) || (hidden && !ms && acts.Any(a => a.Prog.Length > 0 && !Trusted(a.Prog))))
                        // "task \X: program [status] => arguments ..." like every item line (up to 0.8.0 the arguments came after a double blank)
                        c.Find(fi.CreationTimeUtc, $"task {Rules.Fix(name)}{(hidden ? " (hidden)" : "")}: {Log.Item(first.Path ?? "(no action)", first.Status)}",
                               string.IsNullOrEmpty(first.Args) ? null : "arguments " + first.Args, taskFl);   // time = task file created
                }
                catch (UnauthorizedAccessException) when (Rules.Whitelist && LockedTasks.Contains(f.Substring(root.Length))) { lockedTasks++; }
                catch (Exception e) { c.Err.Add("Task " + f + ": " + e.Message); }
            }
            var notes = new List<string>();
            if (publisherTasks.Count > 0)
                notes.Add($"{Util.Plural(publisherTasks.Values.Sum(), "task", "tasks")} of well-known publishers, validly signed (" +
                          string.Join(", ", publisherTasks.OrderByDescending(kv => kv.Value).Select(kv => $"{kv.Key} {kv.Value}")) + ")");
            if (staleTasks > 0) notes.Add($"{Util.Plural(staleTasks, "Windows task", "Windows tasks")} whose program a Windows update removed (Location\\Notifications, USO_UxBroker)");
            if (lockedTasks > 0) notes.Add($"{Util.Plural(lockedTasks, "Windows task", "Windows tasks")} only SYSTEM can read (Pwdless\\IntelligentPwdlessTask)");
            if (notes.Count > 0) c.Out.Comment("Hidden: " + string.Join("; ", notes) + "; -nowhitelist lists them.");
            foreach (var r in trows.OrderBy(r => r.T))
            {
                tt.Add(r.F);
                tt.Aggr(r.Aggr);
                foreach (var m in r.More) { int i = m.IndexOf(": "); tt.More(m.Substring(0, i), m.Substring(i + 2)); }
            }
            tt.WriteTo(c.Out);

            // Task Scheduler log: registered / updated / deleted (deleted tasks are only here)
            var ev = Ev.Query("Microsoft-Windows-TaskScheduler/Operational", Ev.Ids(106, 140, 141), c.Since, 3000, c.Err);
            ev.Reverse();   // the newest are read (up to the limit), listed oldest first
            var shown = ev.Where(e => !(Rules.Whitelist && hiddenTasks.Contains(Ev.P(e, 0)))).ToList();   // deleted tasks are always shown
            if (shown.Count > 0)
            {
                c.Out.Sub("Task Scheduler events (registered, updated, deleted)");
                var tet = new Table("@time", "[kind", "[event", "=change", "*task", "by");
                foreach (var e in shown)
                {
                    var t = e.TimeCreated?.ToUniversalTime();
                    var what = e.Id == 106 ? "registered" : e.Id == 140 ? "updated" : "DELETED";
                    var text = $"task {Rules.Fix(Ev.P(e, 0))} {what}{(Ev.P(e, 1).Length > 0 ? " by " + Ev.P(e, 1) : "")}";
                    tet.Add(Log.T(t), "task", e.Id.ToString(), what, Rules.Fix(Ev.P(e, 0)), Ev.P(e, 1));
                    c.Observe("task", Ev.P(e, 0), t, text);
                    c.Event(t, "TSK", null, text: text);
                    if (e.Id == 141) c.Find(t, text, null, Rules.InfoFlag("!task-deleted"));
                }
                tet.WriteTo(c.Out);
            }
            foreach (var e in ev) e.Dispose();
        }

        void Startup()
        {
            c.Out.Sub("Startup folders (all items)", "time = item created; target: what a shortcut starts");
            var stt = new Table("@time", "[kind", "!status", "<flags", "*item");
            var dirs = new List<string> { Path.Combine(Ctx.Env("ProgramData") ?? "", @"Microsoft\Windows\Start Menu\Programs\Startup") };
            dirs.AddRange(c.Profiles.Select(p => Path.Combine(p.Path, @"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup")));
            bool any = false;
            foreach (var d in dirs.Where(Directory.Exists))
            {
                foreach (var f in new DirectoryInfo(d).GetFiles().Where(f => !f.Name.Equals("desktop.ini", StringComparison.OrdinalIgnoreCase)))
                {
                    any = true;
                    var line = c.File(f.FullName) + Rules.FlagText(Rules.Flags(f.FullName));
                    string target = null;
                    if (f.Extension.Equals(".lnk", StringComparison.OrdinalIgnoreCase))
                        try { var l = Lnk.Parse(c.ReadLocked(f.FullName)); if (l?.Target != null) target = (l.Target.Contains(" ") ? "\"" + l.Target + "\"" : l.Target) + (string.IsNullOrEmpty(l.Args) ? "" : " " + l.Args); } catch { }
                    var sf = c.F(f.FullName);
                    stt.Add(Log.T(f.CreationTimeUtc), "startup", sf.Status, Rules.FlagCol(Rules.Flags(f.FullName)), sf.Path);
                    c.Observe("path", f.FullName, f.CreationTimeUtc);
                    if (target != null)
                    {
                        var pf = ProgF(target, out var prog, out var fl);
                        c.Observe("cmd", target, f.CreationTimeUtc, "Startup item " + line + " -> " + Log.Item(pf.Path, pf.Status));
                        if (Rules.DrivePath.IsMatch(prog ?? "")) { c.Observe("path", prog, f.CreationTimeUtc); c.Relate(f.FullName, prog); }
                        var ta = Cmd.Args(target);
                        stt.More("target", Log.Item(pf.Path, pf.Status, ta.Length > 0 ? "arguments " + Rules.Fix(ta) : null, Rules.FlagCol(fl)));
                        var mods = Modules(prog);
                        foreach (var m in mods) stt.More("module", m);
                        if (Aggr.On && Rules.Flags(f.FullName).Count == 0 && AggrProgram(prog, ta, fl, mods.Count)) stt.Aggr(AggrTrusted);
                        if (Rules.Strong(fl).Count > 0 || fl.Contains("!lolbin"))
                        {
                            // a shortcut that starts a Windows tool (mshta, rundll32, ...): at least context, when nothing else flags it
                            var stFl = Rules.Flags(f.FullName).Concat(fl).ToList();
                            if (Rules.Strong(stFl).Count == 0) stFl.Add("!startup-item");
                            c.Find(f.CreationTimeUtc, "Startup item " + c.File(f.FullName) + " -> " + c.File(prog), null, stFl);
                        }
                    }
                    else if (!f.Extension.Equals(".lnk", StringComparison.OrdinalIgnoreCase))
                    {
                        // a program or script right in a Startup folder runs at every sign-in
                        var sfl = Rules.Flags(f.FullName);
                        if (Rules.ProgramFile(f.FullName) && !sfl.Contains("!suspicious")) sfl.Add("!suspicious");
                        if (Rules.Strong(sfl).Count == 0) sfl.Add("!startup-item");   // a document or data file: context
                        c.Find(f.CreationTimeUtc, "Startup folder file (not a shortcut): " + c.File(f.FullName), null, sfl);
                    }
                    c.Event(f.CreationTimeUtc, "STA", f.FullName, target != null ? "-> " + target : null);
                }
            }
            stt.WriteTo(c.Out);
        }

        /// <summary>DLL of a COM class: per-user registration first (it wins), then the machine one. (dll, "HKLM" or "HKU user")</summary>
        (string Dll, string Where) ComServer(string clsid)
        {
            foreach (var h in c.Hives)
                try
                {
                    using (var k = h.Root.OpenSubKey(@"Software\Classes\CLSID\" + clsid + @"\InprocServer32"))
                    { var v = Convert.ToString(k?.GetValue("")); if (!string.IsNullOrEmpty(v)) return (Environment.ExpandEnvironmentVariables(v), "HKU " + h.User + " (per-user)"); }
                }
                catch { }
            try
            {
                using (var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Classes\CLSID\" + clsid + @"\InprocServer32"))
                { var v = Convert.ToString(k?.GetValue("")); if (!string.IsNullOrEmpty(v)) return (Environment.ExpandEnvironmentVariables(v), "HKLM"); }
            }
            catch { }
            return (null, null);
        }

        void Wmi()
        {
            c.Out.Sub("WMI event subscriptions (no times stored), except Windows' own");
            var defaults = new HashSet<string>(new[] { "SCM Event Log Consumer", "SCM Event Log Filter", "BVTFilter", "BVTConsumer" }, Util.IC);
            try
            {
                var scope = new ManagementScope(@"\\.\root\subscription"); scope.Connect();
                var filters = new Dictionary<string, string>(Util.IC);
                using (var s = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT * FROM __EventFilter")))
                    foreach (ManagementObject o in s.Get()) filters[Convert.ToString(o["__RELPATH"])] = Convert.ToString(o["Query"]);
                var consumers = new Dictionary<string, string>(Util.IC);
                using (var s = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT * FROM __EventConsumer")))
                    foreach (ManagementObject o in s.Get())
                    {
                        var cls = Convert.ToString(o["__CLASS"]);
                        string what = cls == "CommandLineEventConsumer" ? "runs " + (Convert.ToString(o["CommandLineTemplate"]) is string t && t.Length > 0 ? t : Convert.ToString(o["ExecutablePath"]))
                                    : cls == "ActiveScriptEventConsumer" ? "script " + (Convert.ToString(o["ScriptFileName"]) is string f && f.Length > 0 ? f : Util.Clip(Convert.ToString(o["ScriptText"]), 120))
                                    : cls;
                        consumers[Convert.ToString(o["__RELPATH"])] = Rules.Fix(Util.Clip(what, 200));
                    }
                var wt = new Table("[kind", "*filter", ">consumer", "consumer action", "filter query");
                using (var s = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT * FROM __FilterToConsumerBinding")))
                    foreach (ManagementObject o in s.Get())
                    {
                        var fr = Convert.ToString(o["Filter"]); var cr = Convert.ToString(o["Consumer"]);
                        string Nm(string r) { var m = Regex.Match(r ?? "", @"Name=""([^""]*)"""); return m.Success ? m.Groups[1].Value : r; }
                        var fq = filters.FirstOrDefault(kv => fr != null && fr.EndsWith(kv.Key, StringComparison.OrdinalIgnoreCase)).Value;
                        var cw = consumers.FirstOrDefault(kv => cr != null && cr.EndsWith(kv.Key, StringComparison.OrdinalIgnoreCase)).Value ?? "";
                        // Windows' own subscriptions: the names AND what the consumer does must match (malware reuses the names)
                        bool own = defaults.Contains(Nm(fr)) && defaults.Contains(Nm(cr)) &&
                                   (cw == "NTEventLogEventConsumer" || Regex.IsMatch(cw, @"^runs cscript KernCap\.vbs$", Util.RX));
                        c.Observe("cmd", cw, null, $"WMI subscription {Nm(fr)} -> {Nm(cr)}: {cw}");
                        if (Rules.Whitelist && own) continue;
                        wt.Add("wmi", Nm(fr), Nm(cr), cw, fq);
                        c.Find(null, $"WMI subscription {Nm(fr)} -> {Nm(cr)}", cw, new List<string> { "!suspicious" });   // runs code on an event
                    }
                wt.WriteTo(c.Out);
            }
            catch (Exception e) { c.Out.None("cannot read WMI: " + e.Message); }
        }
    }
}
