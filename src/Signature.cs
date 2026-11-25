using System;
using System.Collections.Generic;
using System.Linq;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;

namespace Spor
{
    /// <summary>
    /// Authenticode check of a file: embedded signature (WinVerifyTrust, with revocation check), else Windows catalog.
    /// Status: valid, invalid, revoked, expired, unsigned. Plus signer, certificate thumbprint and the file's version information.
    /// </summary>
    static class Signature
    {
        public class Result
        {
            public string Status = "unsigned";   // valid / invalid / revoked / expired / unsigned
            public string Reason;                // why invalid, or notes for valid ("certificate expired, timestamped", "revocation not checked")
            public string Signer, Thumbprint;
            public bool Catalog;
            public bool Valid => Status == "valid";
        }

        static readonly Regex Signable = new Regex(@"\.(exe|dll|sys|scr|ocx|cpl|drv|com|efi|msi|msp|appx|msix)$", Util.RX);
        static readonly Regex Versioned = new Regex(@"\.(exe|dll|sys|scr|ocx|cpl|drv|com|efi|mui)$", Util.RX);
        static readonly Dictionary<string, Result> cache = new Dictionary<string, Result>(Util.IC);
        static bool online = true;   // revocation check may download CRLs; switched off when the PC is offline or it is slow

        public static bool Applies(string path) => Signable.IsMatch(path ?? "");

        /// <summary>Forget cached results (a new scan in the same window must see replaced files).</summary>
        static readonly Dictionary<string, uint> catalogs = new Dictionary<string, uint>(Util.IC);
        public static void Reset() { cache.Clear(); catalogs.Clear(); names.Clear(); online = true; Checks = 0; CheckTime = TimeSpan.Zero; Package.Reset(); }

        /// <summary>Signature checks this scan (not the cached ones) and their time: the end line says where the scan's time goes.</summary>
        public static int Checks;
        public static TimeSpan CheckTime;

        public static Result Check(string path)
        {
            if (cache.TryGetValue(path, out var cached)) return cached;
            var sw = Stopwatch.StartNew();
            try { return CheckNew(path); }
            finally { Checks++; CheckTime += sw.Elapsed; }
        }

        static Result CheckNew(string path)
        {
            if (cache.TryGetValue(path, out var r)) return r;
            if (!File.Exists(path)) return new Result { Status = "unsigned", Reason = "file not found" };   // callers check existence first
            // a file that cannot be read has no known signature status (not "unsigned")
            try { using (new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete)) { } }
            catch (Exception e) { return cache[path] = new Result { Status = "no access", Reason = e.Message }; }
            // Store / MSIX package files: signed through the package, not the file
            var pk = Package.Check(path);
            if (pk != null) return cache[path] = pk;
            r = new Result();
            try
            {
                var sw = Stopwatch.StartNew();
                uint rc = Verify(path, true);
                if (online && sw.ElapsedMilliseconds > 4000) online = false;
                if (rc == 0x80092013 || rc == 0x80092012 || rc == 0x800B010E)   // revocation offline / not possible / revocation failure
                {
                    rc = Verify(path, false);
                    if (rc == 0) r.Reason = "revocation not checked (offline)";
                }
                switch (rc)
                {
                    case 0: r.Status = "valid"; break;
                    case 0x800B0100: case 0x800B0003: case 0x800B0001:   // no signature / unknown subject form / no provider: try the catalogs
                        // the file's hash is in a catalog: the catalog itself must carry a valid signature (anyone with admin
                        // rights can register a catalog; Windows checks its signature, so do we)
                        var cat = Catalog(path);
                        if (cat != null)
                        {
                            r.Catalog = true;
                            if (cat.Length == 0) { r.Status = "invalid"; r.Reason = "catalog found but not readable"; return cache[path] = r; }
                            Cert(cat, r); r.Signer = (r.Signer ?? "?") + " (catalog)";
                            if (!catalogs.TryGetValue(cat, out var crc))   // many files share a few big catalogs
                            {
                                crc = Verify(cat, true);
                                if (crc == 0x80092013 || crc == 0x80092012 || crc == 0x800B010E) crc = Verify(cat, false);
                                catalogs[cat] = crc;
                            }
                            if (crc == 0) r.Status = "valid";
                            else { r.Status = crc == 0x800B010C || crc == 0x800B0111 ? "revoked" : "invalid"; r.Reason = $"catalog {Path.GetFileName(cat)} has no valid signature (0x{crc:X8})"; }
                        }
                        return cache[path] = r;
                    case 0x800B010C: r.Status = "revoked"; r.Reason = "certificate revoked"; break;
                    case 0x800B0111: r.Status = "revoked"; r.Reason = "certificate explicitly distrusted (e.g. stolen and blocked)"; break;
                    case 0x800B0101: r.Status = "expired"; r.Reason = "certificate expired and no timestamp"; break;
                    case 0x80096010: r.Status = "invalid"; r.Reason = "file changed after signing (bad digest)"; break;
                    case 0x800B0109: r.Status = "invalid"; r.Reason = "untrusted root (self-signed or unknown issuer)"; break;
                    case 0x800B010A: r.Status = "invalid"; r.Reason = "certificate chain incomplete"; break;
                    case 0x80096019: r.Status = "invalid"; r.Reason = "certificate not valid for code signing"; break;
                    case 0x800B0110: r.Status = "invalid"; r.Reason = "certificate not valid for this use"; break;
                    case 0x80096001: r.Status = "invalid"; r.Reason = "signature malformed"; break;
                    default: r.Status = "invalid"; r.Reason = $"0x{rc:X8}"; break;
                }
                Cert(path, r);
                if (r.Valid && r.Reason == null)
                    try { var c2 = new X509Certificate2(X509Certificate.CreateFromSignedFile(path)); if (c2.NotAfter < DateTime.Now) r.Reason = "certificate expired " + c2.NotAfter.ToString("yyyy-MM-dd") + ", timestamped while valid"; } catch { }
            }
            catch (Exception e) { r.Status = "no access"; r.Reason = e.Message; }
            return cache[path] = r;
        }

        static void Cert(string file, Result r)
        {
            try
            {
                var c = new X509Certificate2(X509Certificate.CreateFromSignedFile(file));
                r.Signer = c.GetNameInfo(X509NameType.SimpleName, false);
                r.Thumbprint = c.Thumbprint;
            }
            catch { }
        }

        /// <summary>"status; signer X; thumbprint Y; note Z" for the FILES section (missing parts left out).</summary>
        public static string Describe(Result r)
        {
            if (r.Status == "unsigned") return "unsigned";
            var l = new List<string> { r.Status };
            if (!string.IsNullOrEmpty(r.Signer)) l.Add("signer " + r.Signer);
            if (!string.IsNullOrEmpty(r.Thumbprint)) l.Add("thumbprint " + r.Thumbprint);
            if (!string.IsNullOrEmpty(r.Reason)) l.Add("note " + r.Reason);
            return string.Join("; ", l);
        }

        /// <summary>Version resource as "file version X; description Y; product Z; company W; original name V" (missing parts left out).</summary>
        public static string Version(string path)
        {
            if (!Versioned.IsMatch(path ?? "")) return null;
            try
            {
                var v = FileVersionInfo.GetVersionInfo(path);
                // control characters out first: a value of only those (a cracked DLL's "\0") is empty, not "file version ;"
                var ver = Util.Clip(v.FileVersion); if (ver.Length == 0) ver = Util.Clip(v.ProductVersion);
                var parts = new[] { ("file version", ver), ("description", v.FileDescription), ("product", v.ProductName), ("company", v.CompanyName), ("original name", v.OriginalFilename) }
                    .Select(x => (x.Item1, Value: Util.Clip(x.Item2))).Where(x => x.Value.Length > 0).Select(x => x.Item1 + " " + x.Value.Replace(";", ",")).ToList();
                return parts.Count == 0 ? "none" : string.Join("; ", parts);
            }
            catch { return null; }
        }

        static readonly Dictionary<string, (string Original, string Internal)> names = new Dictionary<string, (string, string)>(Util.IC);

        /// <summary>OriginalFilename and InternalName of the version resource (null when missing), cached.</summary>
        public static (string Original, string Internal) Names(string path)
        {
            if (string.IsNullOrEmpty(path)) return (null, null);
            if (names.TryGetValue(path, out var r)) return r;
            r = (null, null);
            if (Versioned.IsMatch(path))
                try
                {
                    var v = FileVersionInfo.GetVersionInfo(path);
                    string N(string x) => string.IsNullOrWhiteSpace(x) ? null : x.Trim();
                    r = (N(v.OriginalFilename), N(v.InternalName));
                }
                catch { }
            return names[path] = r;
        }

        // ---- WinVerifyTrust ----
        static Guid GenericVerifyV2 = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct WINTRUST_FILE_INFO
        {
            public uint cbStruct;
            [MarshalAs(UnmanagedType.LPWStr)] public string pcwszFilePath;
            public IntPtr hFile, pgKnownSubject;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct WINTRUST_DATA
        {
            public uint cbStruct;
            public IntPtr pPolicyCallbackData, pSIPClientData;
            public uint dwUIChoice, fdwRevocationChecks, dwUnionChoice;
            public IntPtr pFile;
            public uint dwStateAction;
            public IntPtr hWVTStateData, pwszURLReference;
            public uint dwProvFlags, dwUIContext;
            public IntPtr pSignatureSettings;
        }

        [DllImport("wintrust.dll", CharSet = CharSet.Unicode)]
        static extern uint WinVerifyTrust(IntPtr hwnd, ref Guid action, ref WINTRUST_DATA data);

        static uint Verify(string path, bool revocation)
        {
            var fi = new WINTRUST_FILE_INFO { cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)), pcwszFilePath = path };
            IntPtr pFile = Marshal.AllocHGlobal(Marshal.SizeOf(fi));
            try
            {
                Marshal.StructureToPtr(fi, pFile, false);
                var d = new WINTRUST_DATA
                {
                    cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_DATA)),
                    dwUIChoice = 2,                                   // WTD_UI_NONE
                    fdwRevocationChecks = revocation ? 1u : 0u,       // WTD_REVOKE_WHOLECHAIN / NONE
                    dwUnionChoice = 1,                                // WTD_CHOICE_FILE
                    pFile = pFile,
                    dwStateAction = 0,                                // WTD_STATEACTION_IGNORE
                    // revocation: chain without the root; cached CRLs only once the PC turned out to be offline or slow
                    dwProvFlags = revocation ? 0x80u | (online ? 0u : 0x1000u) : 0x10u | 0x1000u
                };
                return WinVerifyTrust(IntPtr.Zero, ref GenericVerifyV2, ref d);
            }
            finally
            {
                Marshal.DestroyStructure(pFile, typeof(WINTRUST_FILE_INFO));
                Marshal.FreeHGlobal(pFile);
            }
        }

        // ---- catalog lookup (most Windows files are signed through catalogs, not embedded signatures) ----
        [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool CryptCATAdminAcquireContext2(out IntPtr hCatAdmin, IntPtr pgSubsystem, string pwszHashAlgorithm, IntPtr pStrongHashPolicy, uint dwFlags);
        [DllImport("wintrust.dll", SetLastError = true)]
        static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr hCatAdmin, SafeFileHandle hFile, ref uint pcbHash, byte[] pbHash, uint dwFlags);
        [DllImport("wintrust.dll", SetLastError = true)]
        static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr hCatAdmin, byte[] pbHash, uint cbHash, uint dwFlags, IntPtr phPrevCatInfo);
        [DllImport("wintrust.dll")]
        static extern bool CryptCATAdminReleaseCatalogContext(IntPtr hCatAdmin, IntPtr hCatInfo, uint dwFlags);
        [DllImport("wintrust.dll")]
        static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint dwFlags);
        [DllImport("wintrust.dll", CharSet = CharSet.Unicode)]
        static extern bool CryptCATCatalogInfoFromContext(IntPtr hCatInfo, ref CATALOG_INFO psCatInfo, uint dwFlags);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct CATALOG_INFO
        {
            public uint cbStruct;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string wszCatalogFile;
        }

        /// <summary>Path of the catalog that contains the file's hash, or null.</summary>
        static string Catalog(string path)
        {
            foreach (var alg in new[] { "SHA256", "SHA1" })
            {
                if (!CryptCATAdminAcquireContext2(out var adm, IntPtr.Zero, alg, IntPtr.Zero, 0)) continue;
                try
                {
                    using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                    {
                        uint n = 0;
                        CryptCATAdminCalcHashFromFileHandle2(adm, fs.SafeFileHandle, ref n, null, 0);
                        if (n == 0 || n > 256) continue;
                        var h = new byte[n];
                        if (!CryptCATAdminCalcHashFromFileHandle2(adm, fs.SafeFileHandle, ref n, h, 0)) continue;
                        var ci = CryptCATAdminEnumCatalogFromHash(adm, h, n, 0, IntPtr.Zero);
                        if (ci == IntPtr.Zero) continue;
                        try
                        {
                            var info = new CATALOG_INFO { cbStruct = (uint)Marshal.SizeOf(typeof(CATALOG_INFO)) };
                            return CryptCATCatalogInfoFromContext(ci, ref info, 0) ? info.wszCatalogFile : "";
                        }
                        finally { CryptCATAdminReleaseCatalogContext(adm, ci, 0); }
                    }
                }
                catch { }
                finally { CryptCATAdminReleaseContext(adm, 0); }
            }
            return null;
        }
    }
}
