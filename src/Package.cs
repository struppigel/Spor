using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using System.Xml;

namespace Spor
{
    /// <summary>
    /// Signature of a file in an installed Store / MSIX package (Program Files\WindowsApps\&lt;package&gt;\...). These files carry no
    /// Authenticode signature of their own; the package does:
    ///   AppxSignature.p7x  = "PKCX" + PKCS#7 signature over a digest list that includes the SHA256 of AppxBlockMap.xml ("AXBM")
    ///   AppxBlockMap.xml   = per file: size and a hash per 64 KB block
    /// Valid = the PKCS#7 signature verifies, its certificate chains to a trusted root, the block map hash matches the signed one,
    /// and the file's size and block hashes match the block map.
    /// </summary>
    static class Package
    {
        // installed packages only: C:\Program Files\WindowsApps\<package>\ or <drive>:\WindowsApps\<package>\ (not the app alias
        // folder AppData\Local\Microsoft\WindowsApps)
        static readonly Regex Root = new Regex(@"^([a-z]:\\(?:Program Files\\)?WindowsApps\\[^\\]+)\\(.+)$", Util.RX);
        const string CodeSigning = "1.3.6.1.5.5.7.3.3", SpcIndirectData = "1.3.6.1.4.1.311.2.1.4";

        public static void Reset() => cache.Clear();

        class Pkg
        {
            public string Error, Signer, Thumbprint, Note;
            public string HashMethod;
            public Dictionary<string, (long Size, List<string> Blocks)> Files;
        }
        static readonly Dictionary<string, Pkg> cache = new Dictionary<string, Pkg>(Util.IC);

        public static bool IsPackaged(string path) => Root.IsMatch(path ?? "");

        /// <summary>null if the file is not in a package folder; else a filled Result.</summary>
        public static Signature.Result Check(string path)
        {
            var m = Root.Match(path ?? "");
            if (!m.Success) return null;
            var r = new Signature.Result();
            var pkg = Load(m.Groups[1].Value);
            if (pkg.Error != null) { r.Status = pkg.Error == "unsigned" ? "unsigned" : "invalid"; r.Reason = pkg.Error == "unsigned" ? null : pkg.Error; return r; }
            r.Signer = pkg.Signer + " (package)"; r.Thumbprint = pkg.Thumbprint;
            if (!pkg.Files.TryGetValue(m.Groups[2].Value, out var bm)) { r.Status = "invalid"; r.Reason = "file is not part of the signed package"; return r; }
            try
            {
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1 << 16))
                using (var h = HashAlgorithm.Create(pkg.HashMethod))
                {
                    if (fs.Length != bm.Size) { r.Status = "invalid"; r.Reason = "file size differs from the signed package"; return r; }
                    var buf = new byte[65536];
                    for (int i = 0; ; i++)
                    {
                        int n = 0, k;
                        while (n < buf.Length && (k = fs.Read(buf, n, buf.Length - n)) > 0) n += k;
                        if (n == 0) { if (i != bm.Blocks.Count) { r.Status = "invalid"; r.Reason = "block count differs from the signed package"; return r; } break; }
                        if (i >= bm.Blocks.Count || Convert.ToBase64String(h.ComputeHash(buf, 0, n)) != bm.Blocks[i])
                        { r.Status = "invalid"; r.Reason = "file changed after the package was signed"; return r; }
                        if (n < buf.Length) { if (i + 1 != bm.Blocks.Count) { r.Status = "invalid"; r.Reason = "block count differs from the signed package"; return r; } break; }
                    }
                }
            }
            catch (Exception e) { r.Status = "invalid"; r.Reason = "cannot read: " + e.Message; return r; }
            r.Status = "valid"; r.Reason = pkg.Note;
            return r;
        }

        static Pkg Load(string root)
        {
            if (cache.TryGetValue(root, out var p)) return p;
            p = new Pkg();
            try
            {
                var sigFile = Path.Combine(root, "AppxSignature.p7x");
                var bmFile = Path.Combine(root, "AppxBlockMap.xml");
                if (!File.Exists(sigFile) || !File.Exists(bmFile)) { p.Error = "unsigned"; return cache[root] = p; }
                var raw = File.ReadAllBytes(sigFile);
                if (raw.Length < 8 || raw[0] != 'P' || raw[1] != 'K' || raw[2] != 'C' || raw[3] != 'X') { p.Error = "package signature malformed"; return cache[root] = p; }
                var cms = new SignedCms();
                cms.Decode(raw.Skip(4).ToArray());
                if (cms.ContentInfo.ContentType.Value != SpcIndirectData) { p.Error = "package signature is not a code signature"; return cache[root] = p; }
                try { cms.CheckSignature(true); } catch (Exception e) { p.Error = "package signature does not verify: " + e.Message; return cache[root] = p; }
                var cert = cms.SignerInfos[0].Certificate;
                p.Signer = cert.GetNameInfo(X509NameType.SimpleName, false); p.Thumbprint = cert.Thumbprint;
                using (var chain = new X509Chain())
                {
                    chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                    chain.ChainPolicy.VerificationFlags = X509VerificationFlags.IgnoreNotTimeValid;
                    chain.ChainPolicy.ApplicationPolicy.Add(new Oid(CodeSigning));   // a website (TLS) certificate must not pass
                    foreach (var x in cms.Certificates) chain.ChainPolicy.ExtraStore.Add(x);
                    if (!chain.Build(cert))
                    {
                        var st = string.Join(", ", chain.ChainStatus.Select(s => s.StatusInformation.Trim()).Where(s => s.Length > 0).Distinct());
                        p.Error = "package certificate not trusted" + (st.Length > 0 ? " (" + st + ")" : ""); return cache[root] = p;
                    }
                }
                if (cert.NotAfter < DateTime.Now) p.Note = "certificate expired " + cert.NotAfter.ToString("yyyy-MM-dd") + " (package signature)";
                // the signed digest list contains "AXBM" + hash of the block map
                var content = cms.ContentInfo.Content;
                int at = -1;
                for (int i = 0; i + 4 + 32 <= content.Length; i++)
                    if (content[i] == 'A' && content[i + 1] == 'X' && content[i + 2] == 'B' && content[i + 3] == 'M') { at = i + 4; break; }
                if (at < 0) { p.Error = "package signature has no block map hash"; return cache[root] = p; }
                var bmBytes = File.ReadAllBytes(bmFile);
                using (var sha = SHA256.Create())
                    if (!sha.ComputeHash(bmBytes).SequenceEqual(content.Skip(at).Take(32))) { p.Error = "block map changed after signing"; return cache[root] = p; }
                var doc = new XmlDocument(); doc.Load(new MemoryStream(bmBytes));
                var hm = doc.DocumentElement.GetAttribute("HashMethod");
                p.HashMethod = hm.EndsWith("sha512") ? "SHA512" : hm.EndsWith("sha384") ? "SHA384" : "SHA256";
                p.Files = new Dictionary<string, (long, List<string>)>(Util.IC);
                foreach (XmlElement f in doc.DocumentElement.ChildNodes.OfType<XmlElement>().Where(e => e.LocalName == "File"))
                    p.Files[f.GetAttribute("Name")] = (long.Parse(f.GetAttribute("Size")), f.ChildNodes.OfType<XmlElement>().Where(b => b.LocalName == "Block").Select(b => b.GetAttribute("Hash")).ToList());
            }
            catch (Exception e) { p.Error = "package signature unreadable: " + e.Message; }
            return cache[root] = p;
        }
    }
}
