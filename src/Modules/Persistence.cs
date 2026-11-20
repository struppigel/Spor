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

        public void Execute(Ctx ctx)
        {
            c = ctx;
            RunKeys();
            Services();
            Tasks();
            Startup();
            Wmi();
        }

        /// <summary>Program of a command: path, flags, [gone]/[unsigned].</summary>
        string Show(string cmd, out string prog, out List<string> fl)
        {
            prog = Cmd.Program(cmd, c.WinDir);
            fl = Rules.Flags(prog);
            if (Rules.Lol.IsMatch(prog) && !fl.Contains("!lolbin")) fl.Add("!lolbin");
            if (Names.RenamedDetail(c, c.RealCase(prog)) != null) fl.Add(Names.RenamedFlag);
            return Rules.DrivePath.IsMatch(prog) ? c.File(prog) : Rules.Fix(prog);
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
        readonly HashSet<string> hiddenTasks = new HashSet<string>(Util.IC);

        void RunKeys()
        {
            c.Out.Sub("Run keys (all entries)", "time = when the key was last changed (Windows stores no time per entry)");
            var rt = new Table("@time", "[kind", "!status", "<flags", "*entry", ">program", "arguments", "value");
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
                        foreach (var n in names)
                        {
                            var cmd = Convert.ToString(key.GetValue(n)) ?? "";
                            var pf = ProgF(cmd, out var prog, out var fl);
                            progs.Add(n);
                            // value: the value name as stored (it can contain backslashes, so it cannot be cut from the entry reliably)
                            rt.Add(Log.T(t), kind, pf.Status, Rules.FlagCol(fl), k.Name + "\\" + Rules.Fix(n), pf.Path, Rules.Fix(Cmd.Args(cmd)), Rules.Fix(n));
                            foreach (var m in Modules(prog)) rt.More("module", m);
                            if (Rules.Strong(fl).Count > 0) c.Find(t, $"Run entry {Rules.Fix(n)} = {c.File(prog)}{Rules.FlagText(fl)}", "key changed");
                        }
                        c.Event(t, "AUT", null, text: $"{k.Name} changed (now: {string.Join(", ", progs)})");
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
                            if (Rules.Whitelist && Trusted(prog, cmd == dll ? null : Cmd.Args(ip)) && Rules.Strong(fl).Count == 0) continue;
                            var start = Convert.ToInt32(k.GetValue("Start") ?? -1);
                            var st = start == 0 ? "boot" : start == 1 ? "system" : start == 2 ? "auto" : start == 3 ? "manual" : start == 4 ? "disabled" : "?";
                            var t = Native.LastWrite(k);
                            var type = Convert.ToInt32(k.GetValue("Type") ?? 0);
                            var kind = (type & 0xF) != 0 ? "driver" : "service";   // 1 kernel driver, 2 file system driver, 8 recognizer; 0x10/0x20 services
                            // svchost-hosted: the DLL is what FRST lists and links; sub-line with its status (it is in FILES through ProgF)
                            var dllLine = cmd == dll ? Log.Item(pf.Path, pf.Status, null, Rules.FlagCol(fl)) : null;
                            var svMore = new List<(string Key, string Value)>();
                            if (dllLine != null) svMore.Add(("dll", dllLine));
                            foreach (var m in Modules(prog)) svMore.Add(("module", m));
                            sv.Add((t, new[] { Log.T(t), kind, st, pf.Status, Rules.FlagCol(fl), Rules.Fix(n), pf.Path + (dll != null && cmd == dll ? " (svchost DLL)" : "") }, svMore));
                            if (Rules.DrivePath.IsMatch(prog)) c.Event(t, "SVC", prog, $"service {n} ({st}) changed");
                            else c.Event(t, "SVC", null, text: $"service {n} ({st}) changed: {Util.Clip(Rules.Fix(ip), 120)}");
                            if (Rules.Strong(fl).Count > 0 || (!Trusted(prog) && start <= 2 && Ctx.BadSig(pf.Status))) c.Find(t, $"service {Rules.Fix(n)} ({st}): {disp}{Rules.FlagText(fl)}", "key changed");
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
            foreach (var e in ev)
            {
                var t = e.TimeCreated?.ToUniversalTime();
                var name = Ev.P(e, 0); var ip = Ev.P(e, 1); var acct = Ev.P(e, 4);
                var kind = Regex.IsMatch(Ev.P(e, 2) ?? "", "driver", Util.RX) ? "driver" : "service";
                var pf = ProgF(ip, out var prog, out var fl);
                var disp = Log.Item(pf.Path, pf.Status);
                // svchost-hosted: the event has no DLL; the service key (if it is still there) has it, and the DLL decides
                string dllLine = null; string dprog = null; List<string> dfl = null;
                if (Regex.IsMatch(prog ?? "", @"\\svchost\.exe$", Util.RX) && SvcDll(name) is string dll)
                {
                    var df = ProgF(dll, out dprog, out dfl);
                    dllLine = Log.Item(df.Path, df.Status, null, Rules.FlagCol(dfl));
                }
                bool trusted = dprog != null ? Trusted(dprog) && Rules.Strong(dfl).Count == 0 : Trusted(prog, Cmd.Args(ip));
                if (Rules.Whitelist && trusted && Rules.Strong(fl).Count == 0) { e.Dispose(); continue; }
                it.Add(Log.T(t), kind, acct, pf.Status, Rules.FlagCol(fl), Rules.Fix(name), pf.Path);
                it.More("dll", dllLine);
                foreach (var m in Modules(prog)) it.More("module", m);
                if (Rules.DrivePath.IsMatch(prog)) c.Event(t, "SVC", prog, $"service {name} installed");
                else c.Event(t, "SVC", null, text: $"service {name} installed: {Util.Clip(Rules.Fix(ip), 120)}", flags: fl);
                if (!trusted || Rules.Strong(fl).Count > 0) c.Find(t, $"service installed: {Rules.Fix(name)}: {disp}{Rules.FlagText(fl)}" + (dllLine != null ? ", dll " + dllLine : ""));
                e.Dispose();
            }
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
                "created / changed = task file times; action: = further actions of the task; info: hidden, author");
            var tt = new Table("@created", "[kind", "changed", "!status", "<flags", "*task", ">program", "arguments");
            var trows = new List<(DateTime T, string[] F, List<string> More)>();
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
                        var disp = Log.Item(pf.Path, pf.Status);
                        acts.Add((prog, disp + (args.Length > 0 ? "  " + Rules.Fix(args) : "") + Rules.FlagText(fl), fl, pf.Path, pf.Status, Rules.Fix(args)));
                    }
                    foreach (XmlNode ch in x.SelectNodes("//t:Actions/t:ComHandler/t:ClassId", ns))
                    {
                        // COM handler: the DLL comes from the registry; a per-user CLSID entry overrides the machine one (COM hijacking)
                        var (dll, where) = ComServer(ch.InnerText);
                        if (dll == null) { acts.Add(("", "COM handler " + ch.InnerText, new List<string>(), "COM handler " + ch.InnerText + " (not registered)", "-", "")); continue; }
                        var pf = ProgF(dll, out var prog, out var fl);
                        if (where != "HKLM") fl.Add("!com-hijack");
                        acts.Add((prog, Log.Item(pf.Path, pf.Status) + " (COM handler " + ch.InnerText + ", " + where + ")" + Rules.FlagText(fl), fl, pf.Path + " (COM handler, " + where + ")", pf.Status, ""));
                    }
                    bool ms = name.StartsWith(@"\Microsoft\", StringComparison.OrdinalIgnoreCase);
                    // hidden only if every action runs a trusted program (location + valid signature, not a LOLBin) with harmless arguments;
                    // older than the time window: any task name, else only \Microsoft\ tasks
                    // an unregistered COM handler runs nothing (a per-user registration would have been found first)
                    bool Unregistered((string Prog, string Line, List<string> Fl, string Path, string Status, string Args) a) => a.Prog.Length == 0 && a.Path.EndsWith("(not registered)");
                    bool allTrusted = acts.Count > 0 && acts.All(a => Unregistered(a)
                                                                     || (a.Prog.Length > 0 && Trusted(a.Prog, a.Args) && Rules.Strong(a.Fl).Count == 0 && !a.Fl.Contains("!com-hijack")));
                    if (Rules.Whitelist && allTrusted && (ms || fi.CreationTimeUtc < c.Since || acts.All(Unregistered))) { hiddenTasks.Add(name); continue; }
                    var author = x.SelectSingleNode("//t:RegistrationInfo/t:Author", ns)?.InnerText;
                    var hidden = x.SelectSingleNode("//t:Settings/t:Hidden", ns)?.InnerText == "true";
                    var first = acts.FirstOrDefault();
                    var changed = (fi.LastWriteTimeUtc - fi.CreationTimeUtc).TotalMinutes > 2;
                    var more = acts.Skip(1).Select(a => "action: " + Log.Item(a.Path, a.Status, a.Args.Length > 0 ? "arguments " + a.Args : null, Rules.FlagCol(a.Fl))).ToList();
                    var info = string.Join(", ", new[] { hidden ? "hidden" : null, string.IsNullOrEmpty(author) ? null : "author " + author }.Where(v => v != null));
                    if (info.Length > 0) more.Add("info: " + info);
                    foreach (var a in acts) more.AddRange(Modules(a.Prog).Select(m => "module: " + m));
                    trows.Add((fi.CreationTimeUtc, new[] { Log.T(fi.CreationTimeUtc), "task", changed ? Log.T(fi.LastWriteTimeUtc) : "-", first.Status ?? "-", Rules.FlagCol(first.Fl),
                                                           Rules.Fix(name), first.Path ?? "(no action)", first.Args ?? "" }, more));
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
                    if (acts.Any(a => Rules.Strong(a.Fl).Count > 0 || (a.Prog.Length > 0 && !Trusted(a.Prog) && Ctx.BadSig(a.Line))) || (hidden && !ms && acts.Any(a => a.Prog.Length > 0 && !Trusted(a.Prog))))
                        c.Find(fi.CreationTimeUtc, $"task {Rules.Fix(name)}{(hidden ? " (hidden)" : "")}: {first.Line}", "task file created");
                }
                catch (Exception e) { c.Err.Add("Task " + f + ": " + e.Message); }
            }
            foreach (var r in trows.OrderBy(r => r.T))
            {
                tt.Add(r.F);
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
                    c.Event(t, "TSK", null, text: text);
                    if (e.Id == 141) c.Find(t, text);
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
                    if (target != null)
                    {
                        var pf = ProgF(target, out var prog, out var fl);
                        var ta = Cmd.Args(target);
                        stt.More("target", Log.Item(pf.Path, pf.Status, ta.Length > 0 ? "arguments " + Rules.Fix(ta) : null, Rules.FlagCol(fl)));
                        foreach (var m in Modules(prog)) stt.More("module", m);
                        if (Rules.Strong(fl).Count > 0 || fl.Contains("!lolbin")) c.Find(f.CreationTimeUtc, "Startup item " + line + " -> " + c.File(prog) + Rules.FlagText(fl), "created");
                    }
                    else if (!f.Extension.Equals(".lnk", StringComparison.OrdinalIgnoreCase)) c.Find(f.CreationTimeUtc, "Startup folder file (not a shortcut): " + line, "created");
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
                        if (Rules.Whitelist && own) continue;
                        wt.Add("wmi", Nm(fr), Nm(cr), cw, fq);
                        c.Find($"WMI subscription {Nm(fr)} -> {Nm(cr)}: {cw}");
                    }
                wt.WriteTo(c.Out);
            }
            catch (Exception e) { c.Out.None("cannot read WMI: " + e.Message); }
        }
    }
}
