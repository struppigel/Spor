using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace Spor
{
    /// <summary>
    /// Known-noise rules: resources/whitelist.txt, or Spor.whitelist.txt next to Spor.exe instead (to try a rule without a new
    /// build). The file says WHERE noise is (folders, names, tasks); the modules say WHEN it may be hidden (validly signed, no
    /// strong flags, ...), and only with the whitelist on (Rules.Whitelist).
    /// </summary>
    static class Whitelist
    {
        public const string OverrideFile = "Spor.whitelist.txt";

        /// <summary>The module noise lists (scope "noise:&lt;module&gt;").</summary>
        public static readonly string[] NoiseModules = { "prefetch", "amcache", "exec", "files" };
        static readonly string[] RegexScopes = { "staging", "script-noise", "breadcrumb" };
        static readonly string[] NameScopes = { "skip-dir", "stale-task", "locked-task" };

        /// <summary>A parsed whitelist file: the values of each scope, in file order.</summary>
        internal sealed class Data
        {
            public readonly Dictionary<string, List<string>> Scopes = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
            public List<string> Of(string scope) => Scopes.TryGetValue(scope, out var l) ? l : new List<string>();
        }

        static Data data;
        static string source;
        static Data D => data ?? (data = Util.DataFile(OverrideFile, Parse, out source));

        /// <summary>Where the rules come from when it is not the built-in file (the override file's path), else null.</summary>
        public static string Source { get { var _ = D; return source; } }

        /// <summary>
        /// (pure) The rules of a whitelist file: "scope TAB value [TAB note]" per line, '#' lines are comments. Throws on an unknown
        /// scope, a line without a value, a regex that does not compile or a stale-task without " => program", so a broken override
        /// falls back to the built-in file (Util.DataFile).
        /// </summary>
        internal static Data Parse(string text)
        {
            var d = new Data();
            var known = new HashSet<string>(NoiseModules.Select(m => "noise:" + m).Concat(RegexScopes).Concat(NameScopes), StringComparer.OrdinalIgnoreCase);
            int no = 0;
            foreach (var raw in (text ?? "").Split('\n'))
            {
                no++;
                var line = raw.TrimEnd('\r');
                if (line.Trim().Length == 0 || line.TrimStart().StartsWith("#", StringComparison.Ordinal)) continue;
                var cols = line.Split('\t');
                var scope = cols[0].Trim();
                var value = cols.Length > 1 ? cols[1].Trim() : "";
                if (!known.Contains(scope)) throw new FormatException($"whitelist line {no}: unknown scope '{scope}'");
                if (value.Length == 0) throw new FormatException($"whitelist line {no}: no value");
                if (scope.StartsWith("noise:", StringComparison.OrdinalIgnoreCase) || RegexScopes.Contains(scope, StringComparer.OrdinalIgnoreCase))
                    new Regex(value, Util.RX);   // throws ArgumentException on a bad pattern
                if (scope.Equals("stale-task", StringComparison.OrdinalIgnoreCase) && StaleTask(value).Program == null)
                    throw new FormatException($"whitelist line {no}: stale-task needs 'task => program'");
                if (!d.Scopes.TryGetValue(scope, out var l)) d.Scopes[scope] = l = new List<string>();
                l.Add(value);
            }
            return d;
        }

        static (string Task, string Program) StaleTask(string value)
        {
            int i = value.IndexOf(" => ", StringComparison.Ordinal);
            if (i <= 0) return (value, null);
            var prog = value.Substring(i + 4).Trim();
            return (value.Substring(0, i).Trim(), prog.Length > 0 ? prog : null);
        }

        /// <summary>A scope's regex lines joined with "|"; a regex that never matches when the scope has none (not "": that matches everything).</summary>
        internal static string Joined(Data d, string scope)
        {
            var l = d.Of(scope);
            return l.Count > 0 ? string.Join("|", l) : "(?!)";
        }

        /// <summary>The noise list of a module (Prefetch: "prefetch", Amcache, ExecEvidence: "exec", Files), for Rules.Noise.</summary>
        public static string Noise(string module) => Joined(D, "noise:" + module);

        static Regex staging, scriptNoise, breadcrumb;
        /// <summary>Updater staging folders (Rules.InUpdaterStaging), against the path without its drive.</summary>
        public static Regex Staging => staging ?? (staging = new Regex(Joined(D, "staging"), Util.RX));
        /// <summary>NEW FILES: folders where scripts are normal.</summary>
        public static Regex ScriptNoise => scriptNoise ?? (scriptNoise = new Regex(Joined(D, "script-noise"), Util.RX));
        /// <summary>NEW FILES: folders of empty marker files.</summary>
        public static Regex Breadcrumb => breadcrumb ?? (breadcrumb = new Regex(Joined(D, "breadcrumb"), Util.RX));

        static HashSet<string> skipDirs, lockedTasks;
        static Dictionary<string, string> staleTasks;
        /// <summary>NEW FILES: folder names not searched.</summary>
        public static HashSet<string> SkipDirs => skipDirs ?? (skipDirs = new HashSet<string>(D.Of("skip-dir"), Util.IC));
        /// <summary>Windows tasks only SYSTEM can read.</summary>
        public static HashSet<string> LockedTasks => lockedTasks ?? (lockedTasks = new HashSet<string>(D.Of("locked-task"), Util.IC));
        /// <summary>Windows tasks whose System32 program feature updates remove: task -> program.</summary>
        public static Dictionary<string, string> StaleTasks
        {
            get
            {
                if (staleTasks != null) return staleTasks;
                var r = new Dictionary<string, string>(Util.IC);
                foreach (var v in D.Of("stale-task")) { var (t, p) = StaleTask(v); r[t] = p; }
                return staleTasks = r;
            }
        }
    }
}
