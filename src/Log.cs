using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace Spor
{
    /// <summary>
    /// FRST-style log: one item per line, fixed order, no column alignment (so word wrap does not break anything):
    ///   ==================== Title ====================          section
    ///   --- title ---                                               sub-section
    ///   (text)                                                      comment / legend
    ///   time [tags] item [status] => details; name value <==== !flags      record
    ///       key: value                                              belongs to the record above
    /// Status values never occur in paths, "&lt;" is not allowed in paths.
    /// </summary>
    class Log
    {
        public const string TimeFmt = "yyyy-MM-dd HH:mm:ss";
        public const int Width = 100;
        public const string Sep = " | ";   // separates fields inside a continuation value

        public readonly List<string> Lines = new List<string>();

        public void W(string s = "") => Lines.Add(s);

        public void Heading(string title)
        {
            var t = "==================== " + title + " ";
            W(t + new string('=', Math.Max(4, Width - t.Length)));
        }

        public void Sub(string title, string legend = null)
        {
            W();
            W("--- " + title + " ---");
            if (!string.IsNullOrEmpty(legend))
                foreach (var l in legend.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None)) Comment(l);
        }

        public void Comment(string s) => W("(" + s + ")");
        public void None(string why = null) => Comment("none" + (why != null ? ": " + why : ""));

        /// <summary>An item inside a line: "path [status] => details &lt;==== flags", parts with "-" or empty left out.</summary>
        public static string Item(string item, string status = null, string details = null, string flags = null)
        {
            bool Has(string v) => !string.IsNullOrEmpty(v) && v != "-";
            var s = item;
            if (Has(status)) s += " [" + status + "]";
            if (Has(details)) s += " => " + details;
            if (Has(flags)) s += " <==== " + flags;
            return s;
        }

        /// <summary>Always "yyyy-MM-dd HH:mm:ss" with ":" and the Gregorian calendar, whatever the PC's culture.</summary>
        public static string T(DateTime? t) => t.HasValue ? t.Value.ToString(TimeFmt, CultureInfo.InvariantCulture) : "-";

        /// <summary>Longest "a, b, c" piece of a list on one sub-line (the key and indent come on top).</summary>
        public const int ListWidth = 150;

        /// <summary>
        /// (pure) A list cut into ", "-joined pieces of at most `width` characters, never inside an item (an item longer than that is a
        /// piece of its own). For long lists on several "    key: a, b, c" sub-lines instead of one very long line.
        /// </summary>
        public static List<string> Chunks(IEnumerable<string> items, int width = ListWidth)
        {
            var res = new List<string>();
            var cur = "";
            foreach (var it in items)
            {
                if (string.IsNullOrEmpty(it)) continue;
                if (cur.Length > 0 && cur.Length + 2 + it.Length > width) { res.Add(cur); cur = ""; }
                cur = cur.Length == 0 ? it : cur + ", " + it;
            }
            if (cur.Length > 0) res.Add(cur);
            return res;
        }

        /// <summary>"(prefix item, item, ...)" as one comment line.</summary>
        public void Wrap(string prefix, IEnumerable<string> items) => Comment(prefix + string.Join(", ", items));

        /// <summary>The singular of a count unit: "new files" -> "new file", "entries" -> "entry".</summary>
        static string One(string unit) =>
            unit.EndsWith("ies") ? unit.Substring(0, unit.Length - 3) + "y" : unit.EndsWith("s") ? unit.Substring(0, unit.Length - 1) : unit;

        /// <summary>Known-noise locations that were hidden, with counts.</summary>
        public void Hidden(Dictionary<string, int> counts, string unit)
        {
            if (counts.Count == 0) return;
            Sub("Hidden: known-noise locations", "Folders where such files are normal on most PCs; counts only. -nowhitelist lists them.");
            var t = new Table("=count", "*folder");
            foreach (var kv in counts.OrderByDescending(kv => kv.Value).ThenBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase))
                t.Add(Util.Plural(kv.Value, One(unit), unit), kv.Key);
            t.WriteTo(this);
        }
    }

    /// <summary>
    /// Records written as FRST-style lines. A column name starts with a role character:
    ///   @ time (first on the line)      [ tag, shown as [value]       * the item
    ///   > target, shown as "=> value"   ! status, [value] after the target (or the item)
    ///   &lt; flags, shown as "&lt;==== value" at the end     = unlabeled detail     no prefix: labeled detail "name value"
    /// Details follow " => " (or ", " after a target) separated by "; ". "-" or empty values are left out.
    /// </summary>
    class Table
    {
        readonly string[] cols;
        readonly List<(string[] F, List<string> More)> rows = new List<(string[], List<string>)>();
        readonly Dictionary<int, string> aggr = new Dictionary<int, string>();   // row index -> why -aggressive hides it
        readonly Dictionary<(int Row, int More), string> aggrMore = new Dictionary<(int, int), string>();   // sub-lines -aggressive hides

        /// <summary>Hidden by -aggressive per reason, in first-seen order (WriteTo adds them up).</summary>
        public readonly Dictionary<string, int> AggrHidden = new Dictionary<string, int>();

        public Table(params string[] columns) { cols = columns; }
        public int Count => rows.Count;

        public void Add(params string[] f)
        {
            var r = new string[cols.Length];
            for (int i = 0; i < cols.Length; i++) { var v = i < f.Length ? Util.Clip(f[i]) : ""; r[i] = v.Length == 0 ? "-" : v; }
            rows.Add((r, new List<string>()));
        }

        /// <summary>
        /// The last record is noise the aggressive whitelist hides (Aggr): with -aggressive it is counted under `why` instead of
        /// written (with its sub-lines), else written with Aggr.Mark at the end of its first line. A record with a flag other than
        /// !lolbin is never marked (safety net).
        /// </summary>
        public void Aggr(string why) => AggrAt(rows.Count - 1, why);

        /// <summary>Aggr for the record at `index` (0 = the first one added).</summary>
        public void AggrAt(int index, string why)
        {
            if (!global::Spor.Aggr.On || index < 0 || index >= rows.Count || string.IsNullOrEmpty(why)) return;
            var f = rows[index].F;
            for (int i = 0; i < cols.Length; i++)
                if (Role(cols[i]) == '<' && !global::Spor.Aggr.Harmless(global::Spor.Aggr.FlagsOf(f[i]))) return;
            aggr[index] = why;
        }

        /// <summary>True if the last record is marked for the aggressive whitelist.</summary>
        public bool LastMarked => rows.Count > 0 && aggr.ContainsKey(rows.Count - 1);

        /// <summary>True if the last record has sub-lines and -aggressive hides all of them.</summary>
        public bool LastMoreAllMarked
        {
            get
            {
                if (rows.Count == 0) return false;
                int r = rows.Count - 1, n = rows[r].More.Count;
                return n > 0 && Enumerable.Range(0, n).All(i => aggrMore.ContainsKey((r, i)));
            }
        }

        /// <summary>Continuation line for the last record: "    key: value".</summary>
        public void More(string key, string value) => More(key, value, null);

        /// <summary>Continuation line for the record at `index` (0 = the first one added).</summary>
        public void MoreAt(int index, string key, string value)
        {
            if (index >= 0 && index < rows.Count && !string.IsNullOrEmpty(value)) rows[index].More.Add(key + ": " + Util.Clip(value));
        }

        /// <summary>
        /// Continuation line for the last record; why != null: the aggressive whitelist hides it (see Aggr). The caller checks the
        /// line's flags (a sub-line has no flags column).
        /// </summary>
        public void More(string key, string value, string why)
        {
            if (rows.Count == 0 || string.IsNullOrEmpty(value)) return;
            var l = rows[rows.Count - 1].More;
            l.Add(key + ": " + Util.Clip(value));
            if (!string.IsNullOrEmpty(why) && global::Spor.Aggr.On) aggrMore[(rows.Count - 1, l.Count - 1)] = why;
        }

        static char Role(string c) => "@[*>!<=".IndexOf(c[0]) >= 0 ? c[0] : ' ';
        static string Name(string c) => Role(c) == ' ' ? c : c.Substring(1);

        /// <summary>The line format, e.g. "time [sources] file [status] => details &lt;==== flags".</summary>
        string Format()
        {
            var parts = new List<string>();
            string Of(char r) => string.Join(" ", cols.Where(c => Role(c) == r).Select(Name));
            if (cols.Any(c => Role(c) == '@')) parts.Add(Of('@'));
            foreach (var c in cols.Where(c => Role(c) == '[')) parts.Add("[" + Name(c) + "]");
            parts.Add(Of('*'));
            bool target = cols.Any(c => Role(c) == '>');
            if (!target && cols.Any(c => Role(c) == '!')) parts.Add("[" + Of('!') + "]");
            var det = cols.Where(c => Role(c) == '=' || Role(c) == ' ').Select(Name).ToList();
            if (target) parts.Add("=> " + Of('>') + (cols.Any(c => Role(c) == '!') ? " [" + Of('!') + "]" : "") + (det.Count > 0 ? ", " + string.Join("; ", det) : ""));
            else if (det.Count > 0) parts.Add("=> " + string.Join("; ", det));
            if (cols.Any(c => Role(c) == '<')) parts.Add("<==== " + Of('<'));
            return string.Join(" ", parts.Where(p => p.Length > 0));
        }

        string Line(string[] f)
        {
            string V(char r) => string.Join(" ", cols.Select((c, i) => (c, i)).Where(x => Role(x.c) == r && f[x.i] != "-").Select(x => f[x.i]));
            var s = new List<string>();
            var t = V('@'); if (t.Length > 0) s.Add(t);
            for (int i = 0; i < cols.Length; i++) if (Role(cols[i]) == '[' && f[i] != "-") s.Add("[" + f[i] + "]");
            var obj = V('*'); s.Add(obj.Length > 0 ? obj : "-");
            var st = V('!'); var tg = V('>');
            var det = cols.Select((c, i) => (c, i)).Where(x => (Role(x.c) == '=' || Role(x.c) == ' ') && f[x.i] != "-")
                          .Select(x => Role(x.c) == '=' ? f[x.i] : Name(x.c) + " " + f[x.i]).ToList();
            var line = string.Join(" ", s);
            if (tg.Length > 0)
            {
                line += " => " + tg + (st.Length > 0 ? " [" + st + "]" : "");
                if (det.Count > 0) line += ", " + string.Join("; ", det);
            }
            else
            {
                if (st.Length > 0) line += " [" + st + "]";
                if (det.Count > 0) line += " => " + string.Join("; ", det);
            }
            var fl = V('<'); if (fl.Length > 0) line += " <==== " + fl;
            return line;
        }

        public void WriteTo(Log log, string none = null)
        {
            if (rows.Count == 0) { log.None(none); return; }
            bool hide = global::Spor.Aggr.Hide;
            AggrHidden.Clear();
            void Count(string why) => AggrHidden[why] = (AggrHidden.TryGetValue(why, out var n) ? n : 0) + 1;
            if (!hide || aggr.Count < rows.Count)
            {
                log.Comment("line: " + Format());
                log.W();   // explanations above, data below
            }
            for (int i = 0; i < rows.Count; i++)
            {
                bool marked = aggr.TryGetValue(i, out var why);
                if (marked && hide) { Count(why); continue; }
                var r = rows[i];
                log.W(Line(r.F) + (marked ? global::Spor.Aggr.Mark : ""));
                for (int j = 0; j < r.More.Count; j++)
                {
                    bool mm = aggrMore.TryGetValue((i, j), out var mw);
                    if (mm && hide) { Count(mw); continue; }
                    log.W("    " + r.More[j] + (mm && !marked ? global::Spor.Aggr.Mark : ""));
                }
            }
            if (global::Spor.Aggr.Comment(AggrHidden) is string c) log.Comment(c);
        }
    }
}
