using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace Spor
{
    /// <summary>
    /// Minimal read-only SQLite reader: reads whole tables (no SQL). Supports overflow pages and a -wal file next to the database
    /// (Firefox keeps recent changes there). Enough for browser history databases.
    /// </summary>
    class Sqlite
    {
        readonly byte[] db;
        readonly int pageSize, usable;
        readonly Dictionary<uint, byte[]> wal = new Dictionary<uint, byte[]>();   // page number -> newest committed version
        readonly Encoding enc = Encoding.UTF8;

        public Sqlite(byte[] data, byte[] walData = null)
        {
            db = data;
            if (db.Length < 100 || Encoding.ASCII.GetString(db, 0, 15) != "SQLite format 3") throw new Exception("not an SQLite database");
            int ps = (db[16] << 8) | db[17];
            pageSize = ps == 1 ? 65536 : ps;
            usable = pageSize - db[20];
            int te = (int)BE32(db, 56);
            if (te == 2) enc = Encoding.BigEndianUnicode; else if (te == 3) enc = Encoding.Unicode;
            if (walData != null) ReadWal(walData);
        }

        static uint BE32(byte[] b, int o) => (uint)(b[o] << 24 | b[o + 1] << 16 | b[o + 2] << 8 | b[o + 3]);
        static int BE16(byte[] b, int o) => b[o] << 8 | b[o + 1];

        void ReadWal(byte[] w)
        {
            if (w.Length < 32) return;
            uint magic = BE32(w, 0);
            if (magic != 0x377f0682 && magic != 0x377f0683) return;
            int ps = (int)BE32(w, 8);
            if (ps != pageSize) return;
            uint s1 = BE32(w, 16), s2 = BE32(w, 20);
            var pending = new Dictionary<uint, byte[]>();
            for (int o = 32; o + 24 + ps <= w.Length; o += 24 + ps)
            {
                if (BE32(w, o + 8) != s1 || BE32(w, o + 12) != s2) break;   // frames from an older WAL generation
                uint pg = BE32(w, o);
                var data = new byte[ps]; Buffer.BlockCopy(w, o + 24, data, 0, ps);
                pending[pg] = data;
                if (BE32(w, o + 4) != 0)   // commit frame: everything so far is valid
                {
                    foreach (var kv in pending) wal[kv.Key] = kv.Value;
                    pending.Clear();
                }
            }
        }

        byte[] Page(uint n)
        {
            if (wal.TryGetValue(n, out var p)) return p;
            long off = (long)(n - 1) * pageSize;
            if (n == 0 || off + pageSize > db.Length) throw new Exception("page " + n + " out of range");
            var b = new byte[pageSize]; Buffer.BlockCopy(db, (int)off, b, 0, pageSize);
            return b;
        }

        static long Varint(byte[] b, ref int o)
        {
            long v = 0;
            for (int i = 0; i < 8; i++) { byte x = b[o++]; v = (v << 7) | (long)(x & 0x7f); if ((x & 0x80) == 0) return v; }
            return (v << 8) | b[o++];
        }

        /// <summary>All rows of a table b-tree: (rowid, record bytes).</summary>
        IEnumerable<(long RowId, byte[] Rec)> Walk(uint root)
        {
            var st = new Stack<uint>(); st.Push(root);
            var seen = new HashSet<uint>();
            while (st.Count > 0)
            {
                uint pn = st.Pop();
                if (!seen.Add(pn)) continue;
                var p = Page(pn);
                int h = pn == 1 ? 100 : 0;
                byte type = p[h];
                int n = BE16(p, h + 3);
                if (type == 0x05)   // interior table page
                {
                    var kids = new List<uint>();
                    for (int i = 0; i < n; i++) kids.Add(BE32(p, BE16(p, h + 12 + 2 * i)));
                    kids.Add(BE32(p, h + 8));
                    for (int i = kids.Count - 1; i >= 0; i--) st.Push(kids[i]);
                }
                else if (type == 0x0d)   // leaf table page
                {
                    for (int i = 0; i < n; i++)
                    {
                        int o = BE16(p, h + 8 + 2 * i);
                        long len = Varint(p, ref o); long rowid = Varint(p, ref o);
                        yield return (rowid, Payload(p, o, len));
                    }
                }
            }
        }

        byte[] Payload(byte[] p, int o, long len)
        {
            int x = usable - 35;
            if (len <= x) { var r = new byte[len]; Buffer.BlockCopy(p, o, r, 0, (int)len); return r; }
            int m = ((usable - 12) * 32 / 255) - 23;
            int k = (int)(m + ((len - m) % (usable - 4)));
            int local = k <= x ? k : m;
            var res = new byte[len];
            Buffer.BlockCopy(p, o, res, 0, local);
            int got = local; uint next = BE32(p, o + local);
            var seen = new HashSet<uint>();
            while (got < len && next != 0 && seen.Add(next))
            {
                var op = Page(next);
                int take = (int)Math.Min(len - got, usable - 4);
                Buffer.BlockCopy(op, 4, res, got, take);
                got += take; next = BE32(op, 0);
            }
            return res;
        }

        object[] Record(byte[] r)
        {
            int o = 0; long hl = Varint(r, ref o);
            var types = new List<long>();
            while (o < hl) types.Add(Varint(r, ref o));
            var vals = new object[types.Count];
            int d = (int)hl;
            for (int i = 0; i < types.Count; i++)
            {
                long t = types[i];
                switch (t)
                {
                    case 0: vals[i] = null; break;
                    case 1: vals[i] = (long)(sbyte)r[d]; d += 1; break;
                    case 2: vals[i] = (long)(short)(r[d] << 8 | r[d + 1]); d += 2; break;
                    case 3: vals[i] = (long)((r[d] << 16 | r[d + 1] << 8 | r[d + 2]) << 8 >> 8); d += 3; break;
                    case 4: vals[i] = (long)(int)BE32(r, d); d += 4; break;
                    case 5: { long v = 0; for (int j = 0; j < 6; j++) v = (v << 8) | r[d + j]; vals[i] = (v << 16) >> 16; d += 6; break; }
                    case 6: { long v = 0; for (int j = 0; j < 8; j++) v = (v << 8) | r[d + j]; vals[i] = v; d += 8; break; }
                    case 7: { long v = 0; for (int j = 0; j < 8; j++) v = (v << 8) | r[d + j]; vals[i] = BitConverter.Int64BitsToDouble(v); d += 8; break; }
                    case 8: vals[i] = 0L; break;
                    case 9: vals[i] = 1L; break;
                    default:
                        if (t >= 12)
                        {
                            int n = (int)((t - (t % 2 == 0 ? 12 : 13)) / 2);
                            n = Math.Max(0, Math.Min(n, r.Length - d));
                            if (t % 2 == 0) { var b = new byte[n]; Buffer.BlockCopy(r, d, b, 0, n); vals[i] = b; }
                            else vals[i] = enc.GetString(r, d, n);
                            d += n;
                        }
                        break;
                }
            }
            return vals;
        }

        /// <summary>Rows of a table as name -> value (INTEGER PRIMARY KEY columns get the rowid). Empty if the table doesn't exist.</summary>
        public IEnumerable<Dictionary<string, object>> Table(string name)
        {
            uint root = 0; string sql = null;
            foreach (var (_, rec) in Walk(1))
            {
                var v = Record(rec);
                if (v.Length >= 5 && (v[0] as string) == "table" && string.Equals(v[1] as string, name, StringComparison.OrdinalIgnoreCase))
                { root = (uint)Convert.ToInt64(v[3]); sql = v[4] as string; break; }
            }
            if (root == 0) yield break;
            var cols = Columns(sql);
            int pk = cols.FindIndex(c => c.Pk);
            foreach (var (rowid, rec) in Walk(root))
            {
                var v = Record(rec);
                var row = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
                for (int i = 0; i < cols.Count; i++) row[cols[i].Name] = i < v.Length ? v[i] : null;
                if (pk >= 0 && row[cols[pk].Name] == null) row[cols[pk].Name] = rowid;
                yield return row;
            }
        }

        /// <summary>Column names from CREATE TABLE; Pk = INTEGER PRIMARY KEY (rowid alias).</summary>
        static List<(string Name, bool Pk)> Columns(string sql)
        {
            var res = new List<(string, bool)>();
            int a = sql.IndexOf('('), b = sql.LastIndexOf(')');
            if (a < 0 || b <= a) return res;
            var body = sql.Substring(a + 1, b - a - 1);
            var parts = new List<string>(); int depth = 0, start = 0;
            for (int i = 0; i < body.Length; i++)
            {
                if (body[i] == '(') depth++;
                else if (body[i] == ')') depth--;
                else if (body[i] == ',' && depth == 0) { parts.Add(body.Substring(start, i - start)); start = i + 1; }
            }
            parts.Add(body.Substring(start));
            foreach (var p in parts.Select(x => x.Trim()))
            {
                if (Regex.IsMatch(p, @"^(CONSTRAINT|PRIMARY\s+KEY|UNIQUE|CHECK|FOREIGN\s+KEY)\b", RegexOptions.IgnoreCase)) continue;
                var m = Regex.Match(p, @"^(""[^""]+""|\[[^\]]+\]|`[^`]+`|\S+)\s*(.*)$", RegexOptions.Singleline);
                if (!m.Success) continue;
                res.Add((m.Groups[1].Value.Trim('"', '[', ']', '`'), Regex.IsMatch(m.Groups[2].Value, @"^INTEGER\b.*\bPRIMARY\s+KEY\b", RegexOptions.IgnoreCase | RegexOptions.Singleline)));
            }
            return res;
        }

        /// <summary>Opens a database that may be in use: reads it (and its -wal) shared, or through a copy.</summary>
        public static Sqlite Open(Ctx c, string path)
        {
            var data = c.ReadLocked(path);
            byte[] w = null;
            if (File.Exists(path + "-wal")) try { w = c.ReadLocked(path + "-wal"); } catch { }
            return new Sqlite(data, w);
        }
    }
}
