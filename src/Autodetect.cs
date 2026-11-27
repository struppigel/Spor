using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text.RegularExpressions;

namespace Spor
{
    /// <summary>
    /// Known malware: the curated pattern database resources/autodetect.txt (built from FenrisHub's malware rules, rewritten for
    /// what Spor sees). The only family-specific part of Spor: every other rule stays generic. Matches only what the modules already
    /// collected (Ctx.Observe, timeline paths, signer and version caches); no extra file or registry reads. Hits go to the SUMMARY
    /// with !known-malware.
    ///
    /// Speed: every value is scanned once by one Aho-Corasick automaton per kind over the lowercase literals (substring rows and the
    /// key of each regex row); a regex runs only when its key is in the value, and is built on first use with a timeout.
    /// </summary>
    static class Autodetect
    {
        public const string Flag = "!known-malware";
        /// <summary>Plain patterns next to Spor.exe, used instead of the built-in ones (to try new patterns without a new build).</summary>
        public const string OverrideFile = "Spor.autodetect.txt";
        /// <summary>Encrypted patterns next to Spor.exe (the build's obj\...\autodetect.bin), used when there is no OverrideFile.</summary>
        public const string EncryptedOverrideFile = "Spor.autodetect.bin";
        /// <summary>The embedded resource: resources/autodetect.txt, encrypted by the build (PatternCrypt).</summary>
        public const string EmbeddedFile = "Spor.autodetect.bin";
        public static readonly string[] Kinds = { "path", "task", "run", "service", "cmd", "software", "company", "domain", "registry" };
        /// <summary>Hits per family in the SUMMARY; the rest are counted on one more line.</summary>
        public const int PerFamily = 10;
        static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(100);

        internal sealed class Pattern
        {
            public int Line;
            public string Kind, Match, Family, Note, Example, Ids;
            public char Op;            // '=' whole value, '*' substring, '/' regex
            public string Literal;     // lowercase: the value (=), the substring (*), the regex key (/)
            public string Regex;
            Regex rx;
            public bool Timeout;
            public Regex Rx => rx ?? (rx = new Regex(Regex, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RegexTimeout));
            public override string ToString() => $"line {Line}: {Kind} {Match}";
        }

        /// <summary>Patterns of one kind: whole values, and the automaton for substrings and regex keys.</summary>
        internal sealed class Index
        {
            public readonly Dictionary<string, List<Pattern>> Exact = new Dictionary<string, List<Pattern>>(StringComparer.Ordinal);
            public readonly AhoCorasick<Pattern> Ac = new AhoCorasick<Pattern>();
            /// <summary>Regex rows without a key: run on every value (only for kinds with few values, see FewValues).</summary>
            public readonly List<Pattern> Always = new List<Pattern>();
        }

        /// <summary>Kinds with a few hundred values per PC at most: regex rows without a key are allowed there.</summary>
        public static readonly string[] FewValues = { "task", "run", "service", "software", "registry" };

        internal sealed class Db
        {
            public readonly List<Pattern> Patterns = new List<Pattern>();
            public readonly List<string> Errors = new List<string>();
            public readonly Dictionary<string, Index> ByKind = new Dictionary<string, Index>();
            public string Source = "built in";

            /// <summary>The rows that match a value of this kind.</summary>
            public List<Pattern> Match(string kind, string value)
            {
                var res = new List<Pattern>();
                if (string.IsNullOrEmpty(value) || !ByKind.TryGetValue(kind, out var ix)) return res;
                var low = value.Trim().ToLowerInvariant();
                if (kind == "domain")
                {
                    // the name and every parent domain: x.y.evil.com -> y.evil.com -> evil.com
                    low = low.TrimEnd('.');
                    for (var d = low; d.Length > 0; d = d.IndexOf('.') is int i && i >= 0 ? d.Substring(i + 1) : "")
                        if (ix.Exact.TryGetValue(d, out var dl)) res.AddRange(dl);
                }
                else if (ix.Exact.TryGetValue(low, out var el)) res.AddRange(el);
                foreach (var p in ix.Ac.Find(low).Concat(ix.Always))
                {
                    if (p.Op == '*') { res.Add(p); continue; }
                    if (p.Op != '/') continue;
                    try { if (p.Rx.IsMatch(value)) res.Add(p); }
                    catch (RegexMatchTimeoutException) { p.Timeout = true; }
                }
                return res.Distinct().ToList();
            }
        }

        static Db db;
        public static Db Patterns => db ?? (db = Load());

        /// <summary>
        /// The embedded database, or instead (to try new patterns without a new build) Spor.autodetect.txt (plain) or
        /// Spor.autodetect.bin (encrypted) next to Spor.exe. An override that cannot be read, decrypted or parsed falls back to the
        /// built-in patterns; the reason goes to the errors.
        /// </summary>
        static Db Load() => Load(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) ?? ".", Embedded);

        /// <summary>Load, with the folder to look for overrides in and the built-in text (tests).</summary>
        internal static Db Load(string dir, Func<string> builtIn)
        {
            var errors = new List<string>();
            foreach (var (name, encrypted) in new[] { (OverrideFile, false), (EncryptedOverrideFile, true) })
            {
                var file = Path.Combine(dir, name);
                if (!File.Exists(file)) continue;
                try
                {
                    var d = Parse(encrypted ? PatternCrypt.Decrypt(File.ReadAllBytes(file)) : File.ReadAllText(file));
                    d.Source = file;
                    d.Errors.InsertRange(0, errors);
                    return d;
                }
                catch (Exception e) { errors.Add($"autodetect {name}: {e.Message}; not used"); }
            }
            var b = Parse(builtIn());
            b.Errors.InsertRange(0, errors);
            return b;
        }

        /// <summary>The built-in database as text (decrypted); "" if Spor.exe has none.</summary>
        public static string Embedded()
        {
            var bytes = Util.EmbeddedBytes(EmbeddedFile);
            return bytes == null ? "" : PatternCrypt.Decrypt(bytes);
        }

        /// <summary>
        /// Tab-separated rows: kind, match, family, note, example, FenrisHub rule ids. match: "=text" (the whole value),
        /// "*text" (part of it) or "/regex/ key=text" (key: a lowercase literal every match contains; without a key only for the kinds
        /// in FewValues). '#' lines are comments.
        /// A domain row (=) also matches its subdomains, and is searched in command lines too. The built-in file has no domain rows
        /// (malware domains in Spor.exe make antivirus engines flag it); they work in Spor.autodetect.txt.
        /// </summary>
        internal static Db Parse(string text)
        {
            var d = new Db();
            foreach (var k in Kinds) d.ByKind[k] = new Index();
            var lines = (text ?? "").Replace("\r\n", "\n").Split('\n');
            for (int i = 0; i < lines.Length; i++)
            {
                var line = lines[i];
                if (line.Trim().Length == 0 || line.TrimStart().StartsWith("#")) continue;
                var f = line.Split('\t');
                string Err(string why) { d.Errors.Add($"autodetect line {i + 1}: {why}"); return null; }
                if (f.Length < 5) { Err("needs at least 5 tab-separated columns (kind, match, family, note, example)"); continue; }
                var p = new Pattern
                {
                    Line = i + 1, Kind = f[0].Trim().ToLowerInvariant(), Match = f[1], Family = f[2].Trim(), Note = f[3].Trim(), Example = f[4].Trim(),
                    Ids = f.Length > 5 ? f[5].Trim() : "",
                };
                if (!Kinds.Contains(p.Kind)) { Err("unknown kind " + p.Kind); continue; }
                if (p.Match.Length < 2 || p.Family.Length == 0) { Err("match and family must not be empty"); continue; }
                p.Op = p.Match[0];
                var body = p.Match.Substring(1);
                if (p.Op == '=' || p.Op == '*') p.Literal = body.ToLowerInvariant();
                else if (p.Op == '/')
                {
                    int k = body.LastIndexOf("/ key=", StringComparison.Ordinal);
                    if (k >= 0) { p.Regex = body.Substring(0, k); p.Literal = body.Substring(k + 6).ToLowerInvariant(); }
                    else if (body.EndsWith("/") && FewValues.Contains(p.Kind)) p.Regex = body.Substring(0, body.Length - 1);
                    else { Err("a regex is /regex/ key=<literal>" + (body.EndsWith("/") ? $" (without a key only for {string.Join(", ", FewValues)})" : "")); continue; }
                    try { _ = p.Rx; } catch (ArgumentException e) { Err("bad regex: " + e.Message); continue; }
                }
                else { Err("match must start with = * or /"); continue; }
                if (p.Literal != null && p.Literal.Length < 3) { Err("the literal or key must have at least 3 characters"); continue; }
                d.Patterns.Add(p);
                var ix = d.ByKind[p.Kind];
                if (p.Op == '=')
                {
                    if (!ix.Exact.TryGetValue(p.Literal, out var l)) ix.Exact[p.Literal] = l = new List<Pattern>();
                    l.Add(p);
                    if (p.Kind == "domain") d.ByKind["cmd"].Ac.Add(p.Literal, new Pattern
                    {
                        Line = p.Line, Kind = "cmd", Match = "*" + p.Literal, Op = '*', Literal = p.Literal, Family = p.Family, Note = p.Note, Example = p.Example, Ids = p.Ids,
                    });
                }
                else if (p.Literal == null) ix.Always.Add(p);
                else ix.Ac.Add(p.Literal, p);
            }
            foreach (var ix in d.ByKind.Values) ix.Ac.Build();
            return d;
        }

        static readonly Regex Extension = new Regex(@"\.[a-z0-9]{1,5}$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

        /// <summary>A path at the start of a sub-line value ("C:\x\y.dll [unsigned] (side-loaded)" -> "C:\x\y.dll"); null if it has none.</summary>
        internal static string PathOf(string s)
        {
            if (string.IsNullOrEmpty(s) || s.Length < 4 || !char.IsLetter(s[0]) || s[1] != ':' || s[2] != '\\') return null;
            int end = s.Length;
            foreach (var stop in new[] { " [", " => ", "  ", " <====" })
            {
                int i = s.IndexOf(stop, StringComparison.Ordinal);
                if (i > 0 && i < end) end = i;
            }
            // " (" ends it only after a file extension: "Program Files (x86)\" and "setup (1).exe" go on
            for (int i = s.IndexOf(" (", StringComparison.Ordinal); i > 0 && i < end; i = s.IndexOf(" (", i + 1, StringComparison.Ordinal))
                if (Extension.IsMatch(s.Substring(0, i))) { end = i; break; }
            return s.Substring(0, end).Trim();
        }

        /// <summary>Signer / version keys matched by Run; Companies takes only the ones the timeline added after it.</summary>
        static HashSet<string> companiesSeen = new HashSet<string>(Util.IC);

        /// <summary>
        /// The scan, before the timeline: all observed values against the database. A file hit marks its timeline events
        /// (!known-malware, the family first in the details), so its timeline line carries it into SUMMARY; every other hit
        /// (tasks, Run entries, services, software, DNS, command lines, signers, files without an event in the window) is an
        /// [Autodetect] SUMMARY line. Returns the number of hits.
        /// </summary>
        public static int Run(Ctx c)
        {
            companiesSeen = new HashSet<string>(Util.IC);
            c.Err.AddRange(Patterns.Errors);
            // values: what the modules observed, plus every timeline path (also sub-line paths) and the signer/company of checked files;
            // SRUM times are hourly buckets (Bucket), not exact times
            var obs = c.Observed.Select(o => (o.Kind, o.Value, o.T, o.Item, Bucket: false, Quiet: false)).ToList();
            foreach (var e in c.Events)
            {
                bool bucket = e.Src == "SRU";
                if (e.Path != null) obs.Add(("path", e.Path, e.T, null, bucket, false));
                if (e.More != null) foreach (var m in e.More) if (PathOf(m.Value) is string mp) obs.Add(("path", mp, e.T, null, bucket, false));
            }
            // files prefetch entries loaded: they mark their own lines and the program that loaded them, no SUMMARY line of their own
            obs.AddRange(c.ObservedQuiet.Select(o => ("path", o.Path, o.T, (string)null, false, true)));
            return Scan(c, obs.Concat(NewCompanies(c)));
        }

        /// <summary>After the timeline: signers and companies of the files it checked first (SUMMARY lines only).</summary>
        public static int Companies(Ctx c) => Scan(c, NewCompanies(c).ToList());

        static IEnumerable<(string Kind, string Value, DateTime? T, string Item, bool Bucket, bool Quiet)> NewCompanies(Ctx c)
        {
            foreach (var k in c.Signer.Keys.Concat(c.Version.Keys).Distinct(Util.IC).ToList())
            {
                if (!companiesSeen.Add(k)) continue;
                c.Signer.TryGetValue(k, out var sg); c.Version.TryGetValue(k, out var ver);
                yield return ("company", (sg ?? "") + "; " + (ver ?? ""), null, k, false, false);
            }
        }

        /// <summary>
        /// (pure) When a hit happened: the earliest exact time of its observations. An hourly bucket (SRUM) counts only when there is
        /// no exact time: it is only the hour in which SRUM wrote its record.
        /// </summary>
        internal static DateTime? When(IEnumerable<(DateTime? T, bool Bucket)> seen)
        {
            DateTime? exact = null, bucket = null;
            foreach (var s in seen)
                if (s.Bucket) bucket = Min(bucket, s.T); else exact = Min(exact, s.T);
            return exact ?? bucket;
        }

        static int Scan(Ctx c, IEnumerable<(string Kind, string Value, DateTime? T, string Item, bool Bucket, bool Quiet)> obs)
        {
            var d = Patterns;
            // each distinct value is matched once; every observation of it keeps its own item
            var cache = new Dictionary<(string, string), List<Pattern>>();
            // Quiet: seen only as a quiet value (ObserveQuiet), so no SUMMARY line of its own
            var hits = new Dictionary<(string Family, string Item), (List<(DateTime?, bool)> Seen, List<Pattern> P, string File, bool Quiet)>();
            foreach (var o in obs)
            {
                if (string.IsNullOrEmpty(o.Value)) continue;
                var key = (o.Kind, o.Value.ToLowerInvariant());
                if (!cache.TryGetValue(key, out var ps)) cache[key] = ps = d.Match(o.Kind, o.Value);
                if (ps.Count == 0) continue;
                // a file is one item whoever saw it; item texts are built only for hits (c.File is cached)
                var item = o.Kind == "path" ? c.File(o.Value)
                         : o.Kind == "company" ? c.File(o.Item) + " (signer or company)"
                         : o.Item ?? o.Kind + " " + Rules.Fix(o.Value);
                var file = o.Kind == "path" ? o.Value : null;
                foreach (var fam in ps.GroupBy(p => p.Family, Util.IC))
                {
                    var hk = (fam.Key, item);
                    if (!hits.TryGetValue(hk, out var h)) h = (new List<(DateTime?, bool)>(), new List<Pattern>(), file, true);
                    h.Seen.Add((o.T, o.Bucket));   // its time: see When
                    hits[hk] = (h.Seen, h.P.Concat(fam).Distinct().ToList(), h.File ?? file, h.Quiet && o.Quiet);
                }
            }
            foreach (var p in d.Patterns.Where(p => p.Timeout))
            {
                c.Err.Add($"autodetect {p}: the regex took more than {RegexTimeout.TotalMilliseconds} ms on a value and was skipped there");
                p.Timeout = false;
            }

            var found = hits.Select(h => (h.Key, Value: (T: When(h.Value.Seen), h.Value.P, h.Value.File, h.Value.Quiet)));
            foreach (var fam in found.GroupBy(h => h.Key.Family, Util.IC).OrderBy(g => g.Key, Util.IC))
            {
                string Notes((DateTime? T, List<Pattern> P, string File, bool Quiet) h) => string.Join("; ", h.P.Select(p => p.Note).Where(n => n.Length > 0).Distinct());
                // files on the timeline: their line gets the flag; the rest are SUMMARY lines (a quiet value only marks)
                var findings = fam.Where(h => !(h.Value.File != null && Mark(c.Events, h.Value.File, fam.Key, Notes(h.Value))) && !h.Value.Quiet)
                                  .OrderBy(h => h.Value.T ?? DateTime.MaxValue).ToList();
                // what stands for a hit gets its mark too: a Startup shortcut's target, the files in a matched program's folder, the
                // program that loaded a matched file. One mark per file and family ("loaded NODE.EXE and 3 more"); none for a file that
                // is a hit of the family itself (a fake Python's pythonw.exe and the library files it loaded)
                var own = new HashSet<string>(fam.Where(h => h.Value.File != null).Select(h => h.Value.File), Util.IC);
                var marks = new List<(string Target, string Via)>();
                foreach (var h in fam)
                    if (c.Related.TryGetValue(h.Value.File ?? h.Key.Item, out var related))
                        foreach (var r in related)
                            if (!own.Contains(r.Path))
                                marks.Add((r.Path, r.Via ?? "related to " + (h.Value.File != null ? Util.Leaf(h.Value.File) : "a matched installed program")));
                foreach (var g in marks.GroupBy(m => m.Target, Util.IC))
                {
                    var vias = g.Select(m => m.Via).Distinct().ToList();
                    var via = vias[0] + (vias.Count > 1 ? $" and {vias.Count - 1} more" : "");
                    if (!g.Key.EndsWith("\\")) Mark(c.Events, g.Key, fam.Key, via);
                    else if (g.Key.TrimEnd('\\').Count(ch => ch == '\\') >= 3) MarkInside(c.Events, g.Key, fam.Key, via);   // not C:\Program Files\
                }
                foreach (var h in findings.Take(PerFamily))
                {
                    var notes = Notes(h.Value);
                    c.Find(h.Value.T, $"{h.Key.Item} => {fam.Key}" + (notes.Length > 0 ? ": " + notes : "") + " <==== " + Flag);
                }
                if (findings.Count > PerFamily)
                    c.Find($"{fam.Key}: {findings.Count - PerFamily} more items match (see the sections) <==== {Flag}");
            }
            return hits.Count;
        }

        /// <summary>
        /// The timeline events of a file get !known-malware and "known malware family: note" (TEvent.Known). New flag lists, as
        /// modules may share theirs between events. False if the file has no event (it is then a SUMMARY line).
        /// </summary>
        internal static bool Mark(IList<TEvent> events, string path, string family, string note)
        {
            var known = $"known malware {family}" + (string.IsNullOrEmpty(note) ? "" : ": " + note);
            bool any = false;
            foreach (var e in events)
            {
                if (e.Path == null || !e.Path.Equals(path, StringComparison.OrdinalIgnoreCase)) continue;
                if (e.Flags == null || !e.Flags.Contains(Flag)) e.Flags = (e.Flags ?? new List<string>()).Concat(new[] { Flag }).ToList();
                if (e.Known == null) e.Known = known;
                else if (!e.Known.Contains(known)) e.Known += "; " + known;
                any = true;
            }
            return any;
        }

        /// <summary>Mark for the events of every file inside a folder (folder ends with "\"): a known-malware program's install folder.</summary>
        internal static bool MarkInside(IList<TEvent> events, string folder, string family, string note)
        {
            bool any = false;
            foreach (var path in events.Where(e => e.Path != null && e.Path.StartsWith(folder, StringComparison.OrdinalIgnoreCase))
                                       .Select(e => e.Path).Distinct(StringComparer.OrdinalIgnoreCase).ToList())
                any |= Mark(events, path, family, note);
            return any;
        }

        static DateTime? Min(DateTime? a, DateTime? b) => !a.HasValue ? b : !b.HasValue ? a : (a < b ? a : b);
    }

    /// <summary>Aho-Corasick: all stored literals in a text in one pass (lowercase literals and text).</summary>
    sealed class AhoCorasick<T>
    {
        readonly List<Dictionary<char, int>> next = new List<Dictionary<char, int>> { new Dictionary<char, int>() };
        readonly List<int> fail = new List<int> { 0 };
        readonly List<List<T>> outs = new List<List<T>> { null };
        bool built;

        public int Count { get; private set; }

        public void Add(string literal, T value)
        {
            if (built) throw new InvalidOperationException("already built");
            int s = 0;
            foreach (var ch in literal)
            {
                if (!next[s].TryGetValue(ch, out var n))
                {
                    n = next.Count; next[s][ch] = n;
                    next.Add(new Dictionary<char, int>()); fail.Add(0); outs.Add(null);
                }
                s = n;
            }
            (outs[s] ?? (outs[s] = new List<T>())).Add(value);
            Count++;
        }

        /// <summary>Failure links (breadth first); each state's output gets the outputs of its failure state.</summary>
        public void Build()
        {
            var q = new Queue<int>();
            foreach (var n in next[0].Values) { fail[n] = 0; q.Enqueue(n); }
            while (q.Count > 0)
            {
                int r = q.Dequeue();
                foreach (var kv in next[r])
                {
                    int u = kv.Value, f = fail[r];
                    while (f != 0 && !next[f].ContainsKey(kv.Key)) f = fail[f];
                    fail[u] = next[f].TryGetValue(kv.Key, out var v) && v != u ? v : 0;
                    if (outs[fail[u]] != null) (outs[u] ?? (outs[u] = new List<T>())).AddRange(outs[fail[u]]);
                    q.Enqueue(u);
                }
            }
            built = true;
        }

        /// <summary>Every stored value whose literal occurs in the text (each once).</summary>
        public IEnumerable<T> Find(string text)
        {
            if (!built) Build();
            if (Count == 0) yield break;
            HashSet<T> seen = null;
            int s = 0;
            foreach (var ch in text)
            {
                while (s != 0 && !next[s].ContainsKey(ch)) s = fail[s];
                s = next[s].TryGetValue(ch, out var n) ? n : 0;
                if (outs[s] == null) continue;
                foreach (var v in outs[s])
                    if ((seen ?? (seen = new HashSet<T>())).Add(v)) yield return v;
            }
        }
    }
}
