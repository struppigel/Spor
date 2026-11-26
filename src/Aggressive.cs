using System;
using System.Collections.Generic;
using System.Linq;

namespace Spor
{
    /// <summary>
    /// The aggressive whitelist (trial, command line -aggressive only, never in the window): more noise that is hidden on top of the
    /// normal whitelist. Without -aggressive the same lines are listed and end in Mark, so normal logs show over time whether such
    /// a line ever mattered. Rules: docs/.WHITELISTING.md, "Aggressive". Records are marked through Table.Aggr; the table decides
    /// at WriteTo whether a marked row is written with the mark or hidden and counted.
    /// </summary>
    static class Aggr
    {
        /// <summary>Appended to the first line of a record that -aggressive hides, or to a sub-line it hides on its own.</summary>
        public const string Mark = " ~";

        /// <summary>Marks are given only with the whitelist on (-nowhitelist shows everything, unmarked).</summary>
        public static bool On => Rules.Whitelist;

        /// <summary>Marked records are hidden (counted) instead of marked.</summary>
        public static bool Hide => Rules.Whitelist && Rules.Aggressive;

        /// <summary>(pure) True if a line ends in the mark (the first line of a record -aggressive hides).</summary>
        public static bool IsMarked(string line) => line != null && line.EndsWith(Mark, StringComparison.Ordinal);

        /// <summary>
        /// (pure) Flags that never keep a record from being marked: only the quiet !lolbin (a validly signed Windows program).
        /// Any other flag keeps a record visible, whatever the rule says.
        /// </summary>
        public static bool Harmless(IEnumerable<string> flags) => flags == null || flags.All(f => f == "!lolbin");

        /// <summary>(pure) Flags of a flags column ("!a !b"), split.</summary>
        public static List<string> FlagsOf(string column) =>
            string.IsNullOrEmpty(column) || column == "-" ? new List<string>() : column.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries).ToList();

        /// <summary>
        /// (pure) The lines without marked records (a marked line and the indented "key: value" lines under it), marked sub-lines and
        /// the Start / End lines. Between Start and End only (a finished log has none: then every line ending in the mark).
        /// </summary>
        public static IEnumerable<string> Unmarked(IEnumerable<string> lines)
        {
            var all = lines.Where(l => l != null).ToList();
            bool regions = all.Any(l => l == Start), inTable = !regions, skip = false;
            foreach (var l in all)
            {
                if (l == Start) { inTable = true; continue; }
                if (IsSentinel(l)) { inTable = !regions; skip = false; continue; }
                bool marked = inTable && IsMarked(l);
                if (l.StartsWith("    ", StringComparison.Ordinal)) { if (!skip && !marked) yield return l; continue; }
                skip = marked;
                if (!skip) yield return l;
            }
        }

        /// <summary>(pure) A Start or End line (Table.WriteTo), not a line of the log.</summary>
        public static bool IsSentinel(string line) => line != null && line.Length > 0 && line[0] == '\u0001';

        /// <summary>(pure) The lines without the Start / End lines.</summary>
        public static IEnumerable<string> WithoutSentinels(IEnumerable<string> lines) => lines.Where(l => !IsSentinel(l));

        static readonly System.Text.RegularExpressions.Regex Stealer = new System.Text.RegularExpressions.Regex(@"\\(DISCORD[^\\]*|LIGHTCORD|BETTERDISCORD)\\", Util.RX);

        /// <summary>A path in an app token stealers patch and run (Discord and its variants): never marked, whatever the rule.</summary>
        public static bool StealerTarget(string p) => p != null && Stealer.IsMatch(p);

        /// <summary>
        /// Updater staging (Rules.InUpdaterStaging) or one of the aggressive whitelist's staging folders (scope aggr:staging, system
        /// drive only: Google's updater in SystemTemp, Office Click-to-Run's versioned Updates folder).
        /// </summary>
        public static bool Staging(string p)
        {
            if (Rules.InUpdaterStaging(p)) return true;
            var m = Rules.DrivePath.Match(p ?? "");
            return m.Success && m.Groups[1].Value.Equals(Rules.SystemDrive, StringComparison.OrdinalIgnoreCase) && Whitelist.AggrStaging.IsMatch(m.Groups[2].Value);
        }

        /// <summary>
        /// A per-user app's program (scope aggr:pair): in the app's folder in a profile, on disk, validly signed by exactly the app's
        /// signer, no flags, not in a random-named folder. A folder name alone is not enough: sideload kits copy signed hosts anywhere.
        /// </summary>
        public static bool Pair(string p)
        {
            var m = Rules.DrivePath.Match(p ?? "");
            if (!m.Success || Rules.Flags(p).Count > 0 || Names.RandomFolder(p) || !Signature.Applies(p)) return false;
            var rel = m.Groups[2].Value;
            var pairs = Whitelist.AggrPairs.Where(x => x.Folder.IsMatch(rel)).ToList();
            if (pairs.Count == 0) return false;
            try
            {
                if (!System.IO.File.Exists(p)) return false;
                var sg = Signature.Check(p);
                var who = (sg.Signer ?? "").Replace(" (catalog)", "");
                return sg.Valid && pairs.Any(x => x.Signer.Equals(who, StringComparison.OrdinalIgnoreCase));
            }
            catch { return false; }
        }

        static readonly HashSet<string> duplicates = new HashSet<string>();

        /// <summary>
        /// A reason for repeats of a line that stays (the same download again, a WebCache batch copy, the same Run command, the
        /// same service installed again): Finish never lifts such a mark, the line it repeats shows what matters.
        /// </summary>
        public static string Dup(string why) { lock (duplicates) duplicates.Add(why); return why; }

        static bool IsDup(string why) { lock (duplicates) return duplicates.Contains(why); }

        /// <summary>Written before a table with marks (Table.WriteTo); Finish removes it.</summary>
        public const string Start = "\u0001aggr-start";
        const string EndPrefix = "\u0001aggr-end";
        const char Sep = '\u0002';

        /// <summary>Written after a table with marks: the reasons of its marked lines, in order (Table.WriteTo); Finish removes it.</summary>
        public static string EndOf(IEnumerable<string> whys) => EndPrefix + string.Concat(whys.Select(w => Sep + w));

        /// <summary>
        /// (pure) The marks at the end of a scan, when every module's findings are known (DEFENDER runs after most modules): a marked
        /// record or sub-line for which keep(its text) is true loses its mark (another module flagged one of its files, SUMMARY
        /// names one). Not final: that is all, the Start / End lines stay (with the reasons of the marks that are left) for a later
        /// final pass; FILES is built in between and needs every line. Final: the Start / End lines go, and with hide
        /// (-aggressive) the marked lines too, with a "(Hidden by -aggressive: ...)" comment where their table ends (a table that
        /// lost every record loses its "(line: ...)" comment). Only lines between Start and End count as marked: a line whose
        /// data ends in " ~" elsewhere is no mark. Lines before `from` are left as they are.
        /// </summary>
        public static void Finish(List<string> lines, int from, Func<string, bool> keep, bool hide, bool final = true)
        {
            var res = new List<string>(lines.Take(from));
            var whys = new Queue<string>();
            var left = new List<string>();   // not final: the reasons of the marks that stay
            var counts = new Dictionary<string, int>();
            int tableStart = -1, kept = 0;
            bool inTable = false;
            for (int i = from; i < lines.Count;)
            {
                var l = lines[i];
                if (l == Start)
                {
                    // the reasons of this table's marks are on its End line
                    whys.Clear(); left.Clear(); counts.Clear(); kept = 0; inTable = true;
                    for (int j = i + 1; j < lines.Count; j++)
                        if (lines[j].StartsWith(EndPrefix, StringComparison.Ordinal))
                        {
                            foreach (var w in lines[j].Substring(EndPrefix.Length).Split(new[] { Sep }, StringSplitOptions.RemoveEmptyEntries)) whys.Enqueue(w);
                            break;
                        }
                    if (!final) res.Add(Start);
                    tableStart = res.Count;
                    i++;
                    continue;
                }
                if (l.StartsWith(EndPrefix, StringComparison.Ordinal))
                {
                    if (!final) res.Add(EndOf(left));
                    else if (hide && counts.Count > 0)
                    {
                        // nothing of the table is left: its "(line: ...)" comment and the blank line under it go too
                        if (kept == 0 && tableStart >= 0 && tableStart + 1 < res.Count && res[tableStart].StartsWith("(line: ", StringComparison.Ordinal) && res[tableStart + 1].Length == 0)
                            res.RemoveRange(tableStart, 2);
                        res.Add("(" + Comment(counts) + ")");
                    }
                    counts.Clear(); tableStart = -1; inTable = false;
                    i++;
                    continue;
                }
                bool sub = l.StartsWith("    ", StringComparison.Ordinal);
                if (!inTable || !IsMarked(l))
                {
                    if (!sub && l.Length > 0 && !l.StartsWith("(", StringComparison.Ordinal)) kept++;
                    res.Add(l);
                    i++;
                    continue;
                }
                // a marked record: its line and the sub-lines under it; a marked sub-line: itself
                int end = i + 1;
                if (!sub) while (end < lines.Count && lines[end].StartsWith("    ", StringComparison.Ordinal)) end++;
                var why = whys.Count > 0 ? whys.Dequeue() : "other";
                var text = string.Join("\n", lines.Skip(i).Take(end - i));
                if (keep != null && !IsDup(why) && keep(text))
                {
                    res.Add(l.Substring(0, l.Length - Mark.Length));
                    res.AddRange(lines.Skip(i + 1).Take(end - i - 1));
                    if (!sub) kept++;
                }
                else if (final && hide) counts[why] = (counts.TryGetValue(why, out var n) ? n : 0) + 1;
                else
                {
                    res.AddRange(lines.Skip(i).Take(end - i));
                    left.Add(why);
                }
                i = end;
            }
            lines.Clear();
            lines.AddRange(res);
        }

        static readonly HashSet<char> PathEnd = new HashSet<char> { ' ', ',', ';', ')', ']', '"', '\'', '|', '<', '>', '\t', '\n' };

        /// <summary>
        /// (pure) Every way a drive path in a text can end (paths hold blanks: "C:\Program Files (x86)\x.exe" also gives "C:\Program"
        /// and "C:\Program Files"): a check against known paths finds the real one among them.
        /// </summary>
        public static IEnumerable<string> PathCandidates(string text)
        {
            if (string.IsNullOrEmpty(text)) yield break;
            for (int s = text.IndexOf(":\\", StringComparison.Ordinal); s >= 1; s = text.IndexOf(":\\", s + 2, StringComparison.Ordinal))
            {
                int st = s - 1;
                if (!char.IsLetter(text[st]) || (st > 0 && char.IsLetterOrDigit(text[st - 1]))) continue;
                for (int e = s + 2; e <= text.Length; e++)
                    if (e == text.Length || PathEnd.Contains(text[e])) yield return text.Substring(st, e - st);
            }
        }

        /// <summary>(pure) "(Hidden by -aggressive: why (N), why (N).)", null without counts.</summary>
        public static string Comment(IDictionary<string, int> counts)
        {
            if (counts == null || counts.Count == 0) return null;
            return "Hidden by -aggressive: " + string.Join(", ", counts.Select(kv => $"{kv.Key} ({kv.Value})")) + ".";
        }
    }
}
