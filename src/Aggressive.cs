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

        /// <summary>(pure) The lines without marked records (a marked line and the indented "key: value" lines under it) and marked sub-lines.</summary>
        public static IEnumerable<string> Unmarked(IEnumerable<string> lines)
        {
            bool skip = false;
            foreach (var l in lines)
            {
                if (l == null) continue;
                if (l.StartsWith("    ", StringComparison.Ordinal)) { if (!skip && !IsMarked(l)) yield return l; continue; }
                skip = IsMarked(l);
                if (!skip) yield return l;
            }
        }

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

        /// <summary>(pure) "(Hidden by -aggressive: why (N), why (N).)", null without counts.</summary>
        public static string Comment(IDictionary<string, int> counts)
        {
            if (counts == null || counts.Count == 0) return null;
            return "Hidden by -aggressive: " + string.Join(", ", counts.Select(kv => $"{kv.Key} ({kv.Value})")) + ".";
        }
    }
}
