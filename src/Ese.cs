using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace Spor
{
    /// <summary>
    /// Read-only access to an ESE (JET Blue) database through Windows' own esent.dll: SRUM (SRUDB.dat), WebCacheV01.dat.
    /// Works on a copy. A copy of a database in use is "dirty", so its logs are copied too and replayed with esentutl /r first.
    /// </summary>
    class Ese : IDisposable
    {
        const int JET_paramSystemPath = 0, JET_paramTempPath = 1, JET_paramLogFilePath = 2, JET_paramBaseName = 3, JET_paramRecovery = 34,
                  JET_paramEnableIndexChecking = 45, JET_paramDatabasePageSize = 64, JET_paramCreatePathIfNotExist = 100;
        const int JET_DbInfoPageSize = 17, JET_bitDbReadOnly = 1, JET_bitTableReadOnly = 4, JET_MoveFirst = int.MinValue, JET_MoveNext = 1;
        const int JET_wrnColumnNull = 1004, JET_wrnBufferTruncated = 1006, JET_errNoCurrentRecord = -1603;

        [StructLayout(LayoutKind.Sequential)]
        struct JET_COLUMNDEF
        {
            public uint cbStruct, columnid, coltyp;
            public ushort wCountry, langid, cp, wCollate;
            public uint cbMax, grbit;
        }

        [DllImport("esent.dll", CharSet = CharSet.Unicode)] static extern int JetCreateInstance2W(out IntPtr instance, string name, string display, int grbit);
        [DllImport("esent.dll", CharSet = CharSet.Unicode)] static extern int JetSetSystemParameterW(ref IntPtr instance, IntPtr sesid, int paramid, IntPtr lParam, string szParam);
        [DllImport("esent.dll", CharSet = CharSet.Unicode)] static extern int JetGetDatabaseFileInfoW(string file, out int result, int cb, int level);
        [DllImport("esent.dll")] static extern int JetInit(ref IntPtr instance);
        [DllImport("esent.dll", CharSet = CharSet.Unicode)] static extern int JetBeginSessionW(IntPtr instance, out IntPtr sesid, string user, string password);
        [DllImport("esent.dll", CharSet = CharSet.Unicode)] static extern int JetAttachDatabase2W(IntPtr sesid, string file, int maxPages, int grbit);
        [DllImport("esent.dll", CharSet = CharSet.Unicode)] static extern int JetOpenDatabaseW(IntPtr sesid, string file, string connect, out uint dbid, int grbit);
        [DllImport("esent.dll", CharSet = CharSet.Unicode)] static extern int JetOpenTableW(IntPtr sesid, uint dbid, string table, IntPtr parameters, int cb, int grbit, out IntPtr tableid);
        [DllImport("esent.dll", CharSet = CharSet.Unicode)] static extern int JetGetTableColumnInfoW(IntPtr sesid, IntPtr tableid, string column, ref JET_COLUMNDEF def, int cb, int level);
        [DllImport("esent.dll")] static extern int JetMove(IntPtr sesid, IntPtr tableid, int rows, int grbit);
        [DllImport("esent.dll")] static extern int JetRetrieveColumn(IntPtr sesid, IntPtr tableid, uint columnid, byte[] data, int cb, out int actual, int grbit, IntPtr retinfo);
        [DllImport("esent.dll")] static extern int JetCloseTable(IntPtr sesid, IntPtr tableid);
        [DllImport("esent.dll")] static extern int JetCloseDatabase(IntPtr sesid, uint dbid, int grbit);
        [DllImport("esent.dll", CharSet = CharSet.Unicode)] static extern int JetDetachDatabaseW(IntPtr sesid, string file);
        [DllImport("esent.dll")] static extern int JetEndSession(IntPtr sesid, int grbit);
        [DllImport("esent.dll")] static extern int JetTerm(IntPtr instance);

        IntPtr inst, ses; uint dbid; readonly string file; bool attached;

        static void Check(int rc, string what) { if (rc < 0) throw new Exception($"{what} failed (ESE error {rc})"); }

        /// <summary>
        /// Copies the database folder's db and log files (base name e.g. "SRU" or "V01") into work, replays the logs, opens read-only.
        /// </summary>
        public static Ese OpenCopy(Ctx c, string dbPath, string baseName, string work)
        {
            Directory.CreateDirectory(work);
            var dir = Path.GetDirectoryName(dbPath);
            var copy = Path.Combine(work, Path.GetFileName(dbPath));
            c.CopyLocked(dbPath, copy);
            foreach (var f in Directory.GetFiles(dir, baseName + "*.log").Concat(Directory.GetFiles(dir, baseName + "*.chk")).Concat(Directory.GetFiles(dir, baseName + "*.jrs")))
                try { c.CopyLocked(f, Path.Combine(work, Path.GetFileName(f))); } catch { }
            // replay the logs into the copy (soft recovery) in the work folder: logs, checkpoint and database all there (/d = current folder);
            // /i: ignore databases the logs mention that are not there
            Run(Path.Combine(c.WinDir, @"System32\esentutl.exe"), $"/r {baseName} /i /d /o", work);
            return new Ese(copy, work);
        }

        static void Run(string exe, string args, string cwd)
        {
            var psi = new ProcessStartInfo(exe, args) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true, RedirectStandardInput = true, WorkingDirectory = cwd };
            using (var p = Process.Start(psi))
            {
                p.StandardInput.Close();
                p.StandardOutput.ReadToEnd(); p.StandardError.ReadToEnd();
                if (!p.WaitForExit(180000)) try { p.Kill(); } catch { }
            }
        }

        Ese(string path, string work)
        {
            file = path;
            Check(JetGetDatabaseFileInfoW(path, out int pageSize, 4, JET_DbInfoPageSize), "JetGetDatabaseFileInfo");
            // the page size is a global setting: set it while no instance runs (SRUM uses 4 KB pages, WebCache 32 KB)
            var none = IntPtr.Zero;
            Check(JetSetSystemParameterW(ref none, IntPtr.Zero, JET_paramDatabasePageSize, (IntPtr)pageSize, null), "page size " + pageSize);
            Check(JetCreateInstance2W(out inst, "spor" + Guid.NewGuid().ToString("N").Substring(0, 8), "Spor", 0), "JetCreateInstance");
            try
            {
                JetSetSystemParameterW(ref inst, IntPtr.Zero, JET_paramRecovery, IntPtr.Zero, "Off");
                JetSetSystemParameterW(ref inst, IntPtr.Zero, JET_paramCreatePathIfNotExist, (IntPtr)1, null);
                JetSetSystemParameterW(ref inst, IntPtr.Zero, JET_paramEnableIndexChecking, IntPtr.Zero, null);   // don't fail on Unicode index version differences
                var t = Path.Combine(work, "tmp") + "\\";
                JetSetSystemParameterW(ref inst, IntPtr.Zero, JET_paramSystemPath, IntPtr.Zero, t);
                JetSetSystemParameterW(ref inst, IntPtr.Zero, JET_paramLogFilePath, IntPtr.Zero, t);
                JetSetSystemParameterW(ref inst, IntPtr.Zero, JET_paramTempPath, IntPtr.Zero, t);
                JetSetSystemParameterW(ref inst, IntPtr.Zero, JET_paramBaseName, IntPtr.Zero, "spr");
                Check(JetInit(ref inst), "JetInit");
                Check(JetBeginSessionW(inst, out ses, "", ""), "JetBeginSession");
                Check(JetAttachDatabase2W(ses, path, 0, JET_bitDbReadOnly), "JetAttachDatabase");
                attached = true;
                Check(JetOpenDatabaseW(ses, path, null, out dbid, JET_bitDbReadOnly), "JetOpenDatabase");
            }
            catch { Dispose(); throw; }
        }

        /// <summary>Rows of a table with the given columns (missing columns are null). Values: long, double, string, byte[], DateTime (for JET DateTime).</summary>
        public IEnumerable<Dictionary<string, object>> Rows(string table, params string[] columns)
        {
            if (JetOpenTableW(ses, dbid, table, IntPtr.Zero, 0, JET_bitTableReadOnly, out var tid) < 0) yield break;
            try
            {
                var defs = new Dictionary<string, JET_COLUMNDEF>(StringComparer.OrdinalIgnoreCase);
                foreach (var col in columns)
                {
                    var d = new JET_COLUMNDEF { cbStruct = (uint)Marshal.SizeOf(typeof(JET_COLUMNDEF)) };
                    if (JetGetTableColumnInfoW(ses, tid, col, ref d, (int)d.cbStruct, 0) >= 0) defs[col] = d;
                }
                int rc = JetMove(ses, tid, JET_MoveFirst, 0);
                var buf = new byte[4096];
                while (rc >= 0)
                {
                    var row = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
                    foreach (var col in columns)
                    {
                        if (!defs.TryGetValue(col, out var d)) { row[col] = null; continue; }
                        int r = JetRetrieveColumn(ses, tid, d.columnid, buf, buf.Length, out int n, 0, IntPtr.Zero);
                        if (r == JET_wrnBufferTruncated) { buf = new byte[n]; r = JetRetrieveColumn(ses, tid, d.columnid, buf, buf.Length, out n, 0, IntPtr.Zero); }
                        row[col] = r < 0 || r == JET_wrnColumnNull ? null : Convert(d, buf, n);
                    }
                    yield return row;
                    rc = JetMove(ses, tid, JET_MoveNext, 0);
                }
            }
            finally { JetCloseTable(ses, tid); }
        }

        static object Convert(JET_COLUMNDEF d, byte[] b, int n)
        {
            switch (d.coltyp)
            {
                case 1: case 2: return n >= 1 ? (long)b[0] : 0L;                          // bit, unsigned byte
                case 3: return (long)BitConverter.ToInt16(b, 0);                           // short
                case 17: return (long)BitConverter.ToUInt16(b, 0);                         // unsigned short
                case 4: return (long)BitConverter.ToInt32(b, 0);                           // long
                case 14: return (long)BitConverter.ToUInt32(b, 0);                         // unsigned long
                case 5: case 15: return n >= 8 ? BitConverter.ToInt64(b, 0) : 0L;          // currency, long long
                case 6: return (double)BitConverter.ToSingle(b, 0);
                case 7: return BitConverter.ToDouble(b, 0);
                case 8: try { return DateTime.FromOADate(BitConverter.ToDouble(b, 0)); } catch { return null; }   // OLE date
                case 10: case 12:                                                         // text, long text
                    return (d.cp == 1200 ? Encoding.Unicode.GetString(b, 0, n) : Encoding.Default.GetString(b, 0, n)).TrimEnd('\0');
                default: { var r = new byte[n]; Buffer.BlockCopy(b, 0, r, 0, n); return r; }   // binary, long binary, GUID
            }
        }

        public void Dispose()
        {
            if (ses != IntPtr.Zero)
            {
                if (dbid != 0) JetCloseDatabase(ses, dbid, 0);
                if (attached) JetDetachDatabaseW(ses, file);
                JetEndSession(ses, 0); ses = IntPtr.Zero;
            }
            if (inst != IntPtr.Zero) { JetTerm(inst); inst = IntPtr.Zero; }
        }
    }

}
