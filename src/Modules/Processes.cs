using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;

namespace Spor.Modules
{
    /// <summary>
    /// Programs running now: from user-writable folders, unsigned, a LOLBin or interpreter with suspicious arguments, or with an unsigned
    /// module from outside Windows and Program Files loaded (side-loading, DLLs injected from disk). With the parent chain and command line.
    /// Prefetch and BAM can miss a running program (Prefetch off or not written yet; BAM is written late). Spor only reads the process list.
    /// </summary>
    class Processes : IModule
    {
        public string Id => "processes";
        public string Name => "RUNNING PROCESSES";
        public string Description => "programs running now from user-writable folders, unsigned, or with unsigned modules";

        internal sealed class Proc
        {
            public int Pid, Ppid = -1;
            public string Name, Path, CommandLine;
            public DateTime? Created;
            public string Leaf => !string.IsNullOrEmpty(Path) ? Util.Leaf(Path) : Name ?? "?";
        }

        Ctx c;

        public void Execute(Ctx ctx)
        {
            c = ctx;
            var procs = Snapshot(out bool wmi);
            var byPid = procs.GroupBy(p => p.Pid).ToDictionary(g => g.Key, g => g.First());
            int self = Process.GetCurrentProcess().Id;
            int checkedCount = 0, noAccess = 0;
            var hidden = new Dictionary<string, int>(Util.IC);
            var t = new Table("@started", "[pid", "*program", "!status", "=parent", "command line", "<flags");
            foreach (var p in procs.OrderBy(p => p.Created ?? DateTime.MaxValue).ThenBy(p => p.Pid))
            {
                if (p.Pid == self || p.Pid <= 4 || string.IsNullOrEmpty(p.Path) || !Rules.DrivePath.IsMatch(p.Path)) continue;
                checkedCount++;
                var path = c.RealCase(c.Long(p.Path));
                bool outside = !Rules.InTrustedLocation(path);
                bool signedOk = c.SignedOk(path);
                bool argsBad = (Rules.Lol.IsMatch(path) || Rules.Interpreter.IsMatch(path)) && Rules.ArgsSuspicious(Cmd.Args(p.CommandLine));
                var mods = Native.ProcessModules(p.Pid);
                // unsigned modules from outside Windows and Program Files (the first module is the program itself)
                var badMods = (mods ?? new List<string>()).Skip(1).Select(m => c.RealCase(c.Long(m))).Distinct(Util.IC)
                    .Where(m => Rules.DrivePath.IsMatch(m) && !Rules.InTrustedLocation(m) && Signature.Applies(m) && File.Exists(m) && !c.SignedOk(m)).ToList();
                var chain = Chain(p, byPid);
                if (chain.Count > 0 && chain[0].Proc != null && !string.IsNullOrEmpty(chain[0].Proc.Path))   // the direct parent only
                    c.Launches.Add((c.RealCase(c.Long(chain[0].Proc.Path)), path, p.CommandLine, p.Created));
                var extra = new List<string>();   // flags besides the name flags (Rules.Flags), which the timeline adds itself
                if (chain.Any(a => a.Proc != null && Rules.ProxyExec(a.Proc.Path ?? a.Proc.Name, a.Proc.CommandLine, path))) extra.Add("!proxy-exec");
                if (Names.RenamedDetail(c, path) != null) extra.Add(Names.RenamedFlag);
                var hits = Sideload.For(c, path);
                var flags = Rules.Flags(path).Concat(extra).Distinct().ToList();
                if (!(outside || !signedOk || argsBad || badMods.Count > 0 || hits.Count > 0 || Rules.Strong(flags).Count > 0)) continue;
                // whitelist: a program installed per user (outside Windows and Program Files, not in a drop location), validly signed by a
                // well-known publisher, with nothing else to say: counted, not listed
                if (Rules.Whitelist && signedOk && !argsBad && badMods.Count == 0 && hits.Count == 0 && flags.All(x => x == "!lolbin")
                    && !Rules.DropLocation(path) && !Rules.Interpreter.IsMatch(path))
                {
                    var who = (Signature.Check(path).Signer ?? "").Replace(" (catalog)", "");
                    if (Rules.TrustedSigners.Contains(who)) { hidden[who] = (hidden.TryGetValue(who, out var n) ? n : 0) + 1; continue; }
                }
                var f = c.F(path);
                t.Add(Log.T(p.Created), p.Pid.ToString(), f.Path, f.Status, ChainText(chain, wmi), Rules.Fix(Util.Clip(p.CommandLine)), Rules.FlagCol(flags));
                foreach (var h in hits) { t.More("module", Sideload.ModuleLine(c, h)); Sideload.Events(c, h); }
                foreach (var m in badMods.Where(m => !hits.Any(h => h.Dll.Path.Equals(m, StringComparison.OrdinalIgnoreCase))))
                    t.More("module", c.File(m));
                if (mods == null) { t.More("modules", "no access"); noAccess++; }
                var details = $"running, pid {p.Pid}" + (chain.Count > 0 && chain[0].Proc != null ? ", parent " + chain[0].Proc.Leaf : "");
                c.Event(p.Created, "PROC", path, details, extra.Count > 0 ? extra : null);
                if (Rules.Strong(extra).Count > 0 && (!p.Created.HasValue || p.Created < c.Since))
                    c.Find(p.Created, $"running process {f.Path} (pid {p.Pid}), {ChainText(chain, wmi)}{Rules.FlagText(Rules.Strong(extra))}");
            }
            c.Out.Comment($"{checkedCount} processes checked" + (wmi ? "" : " (WMI not available: no parents and command lines)") +
                          (noAccess > 0 ? $"; {noAccess} listed ones without access to their modules (protected processes)" : "") + ".");
            c.Out.Comment("started = process start (UTC); parent = the parent chain, nearest first (exited = the parent is gone);");
            c.Out.Comment("module: = an unsigned module from outside Windows and Program Files loaded in the process.");
            if (hidden.Count > 0)
                c.Out.Comment($"Hidden: {hidden.Values.Sum()} programs installed per user, validly signed by well-known publishers (-nowhitelist lists them): " +
                              string.Join(", ", hidden.OrderByDescending(kv => kv.Value).Select(kv => $"{kv.Key} {kv.Value}")));
            t.WriteTo(c.Out);
        }

        /// <summary>The processes now: Win32_Process (with parents and command lines), else the bare process list.</summary>
        List<Proc> Snapshot(out bool wmi)
        {
            var res = new List<Proc>();
            wmi = true;
            try
            {
                using (var q = new ManagementObjectSearcher(@"\\.\root\cimv2", "SELECT ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine, CreationDate FROM Win32_Process"))
                    foreach (ManagementObject o in q.Get())
                        using (o)
                        {
                            var p = new Proc
                            {
                                Pid = Convert.ToInt32(o["ProcessId"]), Ppid = Convert.ToInt32(o["ParentProcessId"]),
                                Name = o["Name"] as string, Path = o["ExecutablePath"] as string, CommandLine = o["CommandLine"] as string,
                            };
                            if (o["CreationDate"] is string cd) try { p.Created = ManagementDateTimeConverter.ToDateTime(cd).ToUniversalTime(); } catch { }
                            if (string.IsNullOrEmpty(p.Path) && p.Pid > 4) p.Path = Native.ProcessPath(p.Pid);
                            res.Add(p);
                        }
            }
            catch (Exception e) { c.Err.Add("Win32_Process: " + e.Message); res.Clear(); }
            if (res.Count > 0) return res;
            wmi = false;
            foreach (var pr in Process.GetProcesses())
                using (pr)
                {
                    var p = new Proc { Pid = pr.Id, Name = pr.ProcessName + ".exe", Path = pr.Id > 4 ? Native.ProcessPath(pr.Id) : null };
                    try { p.Created = pr.StartTime.ToUniversalTime(); } catch { }
                    res.Add(p);
                }
            return res;
        }

        /// <summary>
        /// The parents of a process, nearest first, up to depth levels. Proc null = exited: no such PID now, or the PID belongs to a
        /// process started after the child (Windows reuses PIDs).
        /// </summary>
        internal static List<(int Pid, Proc Proc)> Chain(Proc p, IDictionary<int, Proc> byPid, int depth = 4)
        {
            var res = new List<(int, Proc)>();
            var seen = new HashSet<int> { p.Pid };
            var cur = p;
            for (int i = 0; i < depth && cur.Ppid > 0; i++)
            {
                int pp = cur.Ppid;
                if (!seen.Add(pp)) break;
                byPid.TryGetValue(pp, out var parent);
                if (parent != null && parent.Created.HasValue && cur.Created.HasValue && parent.Created.Value > cur.Created.Value) parent = null;
                res.Add((pp, parent));
                if (parent == null) break;
                cur = parent;
            }
            return res;
        }

        /// <summary>"parent cmd.exe (4312) &lt; forfiles.exe (4100) &lt; pid 2200 (exited)". No status words in brackets (parsers).</summary>
        internal static string ChainText(List<(int Pid, Proc Proc)> chain, bool known = true)
        {
            if (!known) return "parent unknown";
            if (chain.Count == 0) return "parent none";
            return "parent " + string.Join(" < ", chain.Select(a => a.Proc == null ? $"pid {a.Pid} (exited)" : $"{a.Proc.Leaf} ({a.Pid})"));
        }
    }
}
