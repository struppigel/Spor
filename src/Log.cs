using System;
using System.Collections.Generic;
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

        public static string T(DateTime? t) => t.HasValue ? t.Value.ToString(TimeFmt) : "-";

        /// <summary>"(prefix item, item, ...)" as one comment line.</summary>
        public void Wrap(string prefix, IEnumerable<string> items) => Comment(prefix + string.Join(", ", items));

        /// <summary>Known-noise locations that were hidden, with counts.</summary>
        public void Hidden(Dictionary<string, int> counts, string unit)
        {
            if (counts.Count == 0) return;
            Sub("Hidden: known-noise locations", "Folders where such files are normal on most PCs; counts only. -nowhitelist lists them.");
            var t = new Table("=count", "*folder");
            foreach (var kv in counts.OrderByDescending(kv => kv.Value).ThenBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase))
                t.Add(kv.Value + " " + unit, kv.Key);
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

        public Table(params string[] columns) { cols = columns; }
        public int Count => rows.Count;

        public void Add(params string[] f)
        {
            var r = new string[cols.Length];
            for (int i = 0; i < cols.Length; i++) { var v = i < f.Length ? Util.Clip(f[i]) : ""; r[i] = v.Length == 0 ? "-" : v; }
            rows.Add((r, new List<string>()));
        }

        /// <summary>Continuation line for the last record: "    key: value".</summary>
        public void More(string key, string value)
        {
            if (rows.Count > 0 && !string.IsNullOrEmpty(value)) rows[rows.Count - 1].More.Add(key + ": " + Util.Clip(value));
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
            log.Comment("line: " + Format());
            log.W();   // explanations above, data below
            foreach (var r in rows)
            {
                log.W(Line(r.F));
                foreach (var m in r.More) log.W("    " + m);
            }
        }
    }
}
