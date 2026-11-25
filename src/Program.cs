using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Windows.Forms;

namespace Spor
{
    static class Program
    {
        const string Usage = @"Spor - forensic triage log for malware removal

Without options Spor opens its window. With options it scans without a window:

  -scan            scan with the defaults (profile default)
  -days N          time window for Amcache, execution evidence, ShimCache (default 30)
  -nowhitelist     show everything: no trusted folders, no known-noise folders, no Windows servicing,
                   no inbox/Microsoft driver filtering (flags like !lolbin work the same either way)
  -aggressive      hide more noise (trial: lines it hides are marked in normal logs)
  -noise REGEX     your own known-noise regex, added to each module's list (e.g. \\STEAMAPPS\\COMMON\\)
  -profile NAME    which modules run: default (all except usb), usb (USB worm: prefetch, exec, files, persistence,
                   processes, usb), all
  -modules LIST    comma-separated modules instead of a profile: prefetch, amcache, exec, files, timestomp, downloads,
                   software, persistence, processes, defender, clickfix, remote, network, accounts, drops, usb
  -algo NAME       hash algorithm: SHA256 (default), SHA1 (to compare with Amcache), MD5
  -maxmb N         don't hash files over N MB (default 500)
  -nohash          don't hash files (signatures are still checked)
  -out FILE        log file (default: Spor.txt next to Spor.exe, else on the Desktop)
  -noopen          don't open the log in Notepad when done
  -help            this text
";

        [DllImport("kernel32.dll")] static extern bool AttachConsole(int pid);

        [STAThread]
        static int Main(string[] args)
        {
            // Times and numbers the same on every PC ("2026-11-19 21:09:24", "149.8 s"): parsers read the log.
            // The UI culture stays, so Windows' event messages keep the PC's language.
            CultureInfo.DefaultThreadCurrentCulture = CultureInfo.InvariantCulture;
            Thread.CurrentThread.CurrentCulture = CultureInfo.InvariantCulture;
            if (args.Length == 0)
            {
                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);
                Application.Run(new MainForm());
                return 0;
            }
            AttachConsole(-1);   // command line: write to the console Spor was started from (it is a window program)
            Console.WriteLine();
            Options o;
            try
            {
                o = Parse(args);
                if (o == null) { Console.Write(Usage); return 0; }
            }
            catch (Exception e) { Console.Error.WriteLine(e.Message); Console.Error.Write(Usage); return 2; }

            string path;
            // "[2/5] module ...", then "Writing the log" without a number (done == total), as in the window.
            try { path = Scanner.Run(o, (t, i, n) => Console.WriteLine(i < n ? $"[{i + 1}/{n}] {t}" : t)); }
            catch (Exception e) { Console.Error.WriteLine("Cannot write the log: " + e.Message); return 1; }
            Console.WriteLine("Log: " + path);
            if (!o.NoOpen) OpenLog(path);
            return 0;
        }

        /// <summary>The options of a command line; null for -help. Throws ArgumentException (or FormatException) on a bad one.</summary>
        internal static Options Parse(string[] args)
        {
            var o = new Options();
            for (int i = 0; i < args.Length; i++)
            {
                var a = args[i].TrimStart('-', '/').ToLowerInvariant();
                string Val() => i + 1 < args.Length ? args[++i] : throw new ArgumentException("missing value for " + args[i]);
                switch (a)
                {
                    case "scan": break;
                    case "days": o.Days = int.Parse(Val()); break;
                    case "nowhitelist": case "all": o.Whitelist = false; break;
                    case "aggressive": o.Aggressive = true; break;
                    case "noise": o.ExtraNoise = Val(); new System.Text.RegularExpressions.Regex(o.ExtraNoise); break;
                    case "profile": o.Profile = Val().ToLowerInvariant(); if (Scanner.ProfileModules(o.Profile) == null) throw new ArgumentException("unknown profile " + o.Profile); break;
                    case "modules": o.Modules = new HashSet<string>(Val().Split(',').Select(x => x.Trim()), StringComparer.OrdinalIgnoreCase); break;
                    case "algo": o.Algo = Val().ToUpperInvariant(); if (!new[] { "SHA256", "SHA1", "MD5" }.Contains(o.Algo)) throw new ArgumentException("unknown hash algorithm " + o.Algo); break;
                    case "maxmb": o.MaxMB = int.Parse(Val()); break;
                    case "nohash": o.NoHash = true; break;
                    case "out": o.Out = Val(); break;
                    case "noopen": o.NoOpen = true; break;
                    case "help": case "h": case "?": return null;
                    default: throw new ArgumentException("unknown option " + args[i]);
                }
            }
            if (o.Aggressive && !o.Whitelist) throw new ArgumentException("-aggressive needs the whitelist: not with -nowhitelist");
            if (o.Modules != null)
                foreach (var m in o.Modules) if (!Scanner.All.Any(x => x.Id.Equals(m, StringComparison.OrdinalIgnoreCase))) throw new ArgumentException("unknown module " + m);
            return o;
        }

        public static void OpenLog(string path)
        {
            try { Process.Start(new ProcessStartInfo("notepad.exe", "\"" + path + "\"") { UseShellExecute = true }); } catch { }
        }
    }
}
