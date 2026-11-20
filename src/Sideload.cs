using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.Win32;

namespace Spor
{
    /// <summary>A PE file with what the side-loading rule needs. From disk the parts are read only when asked for; tests give them directly.</summary>
    sealed class PeFile
    {
        public readonly string Path;
        readonly Lazy<(bool Valid, string Signer, string Status)> sig;
        readonly Lazy<string> original;
        readonly Lazy<PeInfo> pe;

        public PeFile(string path, bool signedValid, string signer, string originalName, PeInfo info)
            : this(path, () => (signedValid, signer, signedValid ? "valid" : "unsigned"), () => originalName, () => info) { }

        public PeFile(string path, Func<(bool Valid, string Signer, string Status)> sig, Func<string> original, Func<PeInfo> pe)
        {
            Path = path;
            this.sig = new Lazy<(bool, string, string)>(sig);
            this.original = new Lazy<string>(original);
            this.pe = new Lazy<PeInfo>(() => pe() ?? PeInfo.Empty);
        }

        public string Name => System.IO.Path.GetFileName(Path);
        public bool SignedValid => sig.Value.Valid;
        public string Signer => sig.Value.Signer;
        /// <summary>The signature could not be checked (no access): neither signed nor unsigned.</summary>
        public bool Unknown => sig.Value.Status == "no access";
        public string OriginalName => original.Value;
        public PeInfo Pe => pe.Value;
    }

    /// <summary>A validly signed program next to an unsigned DLL it imports.</summary>
    sealed class SideloadHit
    {
        public PeFile Host, Dll;
        public string ProxyFile, ProxyOriginal;   // a validly signed DLL in the folder whose original name is the side-loaded DLL's name
        public int Forwarded, Exports;            // of the side-loaded DLL: exports that only forward or jump, all named exports

        /// <summary>Most exports forward or jump elsewhere: a proxy in front of the real DLL.</summary>
        public bool ProxyByExports => Exports >= 2 && Forwarded * 2 > Exports;

        public string Evidence =>
            ProxyFile != null ? $"proxy DLL, forwards to {ProxyFile} (original name {ProxyOriginal})"
            : ProxyByExports ? $"exports forwarded: {Forwarded} of {Exports}" : null;

        /// <summary>Details of the DLL's line. No status words in brackets: parsers read those as the line's status.</summary>
        public string DllDetails =>
            "loaded by " + Host.Name + (string.IsNullOrEmpty(Host.Signer) ? "" : " (signed by " + Host.Signer + ")") + (Evidence != null ? "; " + Evidence : "");

        public string HostDetails => "side-loads " + Dll.Name;
    }

    /// <summary>
    /// DLL side-loading (search-order hijacking): a validly signed program, outside Windows and Program Files, imports a DLL that sits next
    /// to it and is not validly signed. Windows loads the DLL from the program's folder first, so the signed program runs the attacker's code.
    /// A proxy DLL forwards the real exports to the renamed original, so the program keeps working.
    /// </summary>
    static class Sideload
    {
        public const string Flag = "!sideload";

        static HashSet<string> known;

        /// <summary>KnownDLLs: always loaded from System32, never from a program's folder.</summary>
        public static ICollection<string> KnownDlls
        {
            get
            {
                if (known != null) return known;
                known = new HashSet<string>(Util.IC);
                try
                {
                    using (var k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs"))
                        if (k != null)
                            foreach (var n in k.GetValueNames())
                                if (k.GetValue(n) is string v && v.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)) known.Add(v);
                }
                catch { }
                return known;
            }
        }

        /// <summary>API sets and KnownDLLs: Windows resolves these itself.</summary>
        public static bool Ignored(string import, ICollection<string> knownDlls) =>
            string.IsNullOrEmpty(import) || import.StartsWith("api-ms-", StringComparison.OrdinalIgnoreCase)
            || import.StartsWith("ext-ms-", StringComparison.OrdinalIgnoreCase) || (knownDlls != null && knownDlls.Contains(import));

        /// <summary>
        /// The side-loaded DLLs of a host program (pure: everything comes from the records). host: an .exe outside trusted locations and
        /// validly signed (an unsigned host is visible anyway and abuses no trust). folderDlls: the DLLs in the host's folder.
        /// Plugin DLLs that a program loads with LoadLibrary (NSIS, Inno Setup) are not imported, so they never match.
        /// </summary>
        public static List<SideloadHit> Decide(PeFile host, IEnumerable<PeFile> folderDlls, ICollection<string> knownDlls)
        {
            var hits = new List<SideloadHit>();
            if (host == null || !host.Path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) || Rules.InTrustedLocation(host.Path)) return hits;
            var dlls = folderDlls.Where(d => !d.Path.Equals(host.Path, StringComparison.OrdinalIgnoreCase)).ToList();
            var candidates = host.Pe.Imports.Where(i => !Ignored(i, knownDlls))
                .Select(i => dlls.FirstOrDefault(d => d.Name.Equals(i, StringComparison.OrdinalIgnoreCase))).Where(d => d != null).ToList();
            if (candidates.Count == 0 || !host.SignedValid) return hits;
            foreach (var dll in candidates)
            {
                if (dll.SignedValid || dll.Unknown) continue;
                var hit = new SideloadHit { Host = host, Dll = dll, Exports = dll.Pe.Exports.Count, Forwarded = dll.Pe.ForwardedExports };
                var proxy = dlls.FirstOrDefault(d => d != dll && !d.Name.Equals(dll.Name, StringComparison.OrdinalIgnoreCase)
                                                     && string.Equals(d.OriginalName, dll.Name, StringComparison.OrdinalIgnoreCase) && d.SignedValid);
                if (proxy != null) { hit.ProxyFile = proxy.Name; hit.ProxyOriginal = proxy.OriginalName; }
                hits.Add(hit);
            }
            return hits;
        }

        /// <summary>A file on disk: signature, version and PE headers read when the rule asks for them.</summary>
        public static PeFile FromDisk(string p) =>
            new PeFile(p, () => { var sg = Signature.Check(p); return (sg.Valid, sg.Signer, sg.Status); }, () => Signature.Names(p).Original, () => Pe.Read(p));

        /// <summary>
        /// The side-loaded DLLs of a program on disk, once per program and scan. Each DLL goes to the SUMMARY once (c.Find).
        /// Callers add the flag and details to their own lines (Files) or call Events (Persistence, Processes).
        /// </summary>
        public static List<SideloadHit> For(Ctx c, string host)
        {
            if (string.IsNullOrEmpty(host) || !Rules.DrivePath.IsMatch(host) || !host.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) return new List<SideloadHit>();
            host = c.RealCase(host);
            if (c.Sideloads.TryGetValue(host, out var hits)) return hits;
            hits = new List<SideloadHit>();
            try
            {
                if (File.Exists(host) && !Rules.InTrustedLocation(host))
                {
                    var folder = System.IO.Path.GetDirectoryName(host);
                    var hostFile = FromDisk(host);
                    // cheap first: only a program that imports a DLL lying next to it needs signatures
                    var imported = hostFile.Pe.Imports.Where(i => !Ignored(i, KnownDlls)).Select(i => System.IO.Path.Combine(folder, i)).Where(File.Exists).ToList();
                    if (imported.Count > 0)
                    {
                        // the imported DLLs always; the others (for a proxy's renamed original) up to 500
                        var dlls = imported.Concat(Directory.EnumerateFiles(folder, "*.dll").Take(500)).Distinct(Util.IC).Select(FromDisk).ToList();
                        hits = Decide(hostFile, dlls, KnownDlls);
                    }
                }
            }
            catch (Exception e) { c.Err.Add("side-loading check of " + host + ": " + e.Message); }
            c.Sideloads[host] = hits;
            foreach (var h in hits)
            {
                var f = c.F(h.Dll.Path);
                DateTime? t = null;
                try { t = File.GetCreationTimeUtc(h.Dll.Path); } catch { }
                c.Find(t, $"DLL side-loading: {f.Path} ({(f.Status == "-" ? "not validly signed" : f.Status)}) imported by {c.RealCase(h.Host.Path)}" +
                          (string.IsNullOrEmpty(h.Host.Signer) ? "" : $" (signed by {h.Host.Signer})") + (h.Evidence != null ? "; " + h.Evidence : ""));
            }
            return hits;
        }

        /// <summary>
        /// Marks the DLL's (or the host's) timeline details of a hit as written; false when they already were. Each module that finds
        /// the hit (files, persistence, processes) calls Events, and the details must reach the timeline only once.
        /// </summary>
        public static bool Claim(Ctx c, SideloadHit h, bool dllLine) =>
            c.SideloadLines.Add((dllLine ? "dll|" : "host|") + h.Dll.Path + "|" + h.Host.Path);

        /// <summary>Timeline lines of a hit, those no module has written yet: the DLL (flagged) and its host, when they are new.</summary>
        public static void Events(Ctx c, SideloadHit h)
        {
            try
            {
                if (Claim(c, h, dllLine: true)) c.Event(File.GetCreationTimeUtc(h.Dll.Path), "NEW", h.Dll.Path, h.DllDetails, new List<string> { Flag });
                if (Claim(c, h, dllLine: false)) c.Event(File.GetCreationTimeUtc(h.Host.Path), "NEW", h.Host.Path, h.HostDetails);
            }
            catch { }
        }

        /// <summary>The DLL as a "module:" sub-line value: "path [status] => details &lt;==== !sideload".</summary>
        public static string ModuleLine(Ctx c, SideloadHit h)
        {
            var f = c.F(h.Dll.Path);
            return Log.Item(f.Path, f.Status, h.DllDetails, Flag);
        }
    }
}
