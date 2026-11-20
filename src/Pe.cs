using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Spor
{
    /// <summary>One exported name: a forwarder ("OTHER.Func"), a short jump stub, or real code.</summary>
    sealed class PeExport
    {
        public string Name;
        public string ForwardTo;   // "OTHER.Func" for a forwarder, else null
        public bool Stub;          // the code is only a jump through a pointer (FF 25), maybe after E9 jumps
        public bool Forwarder => ForwardTo != null;
    }

    /// <summary>What Spor reads from a PE file's headers. Empty (Valid false) for anything that is not a readable PE file.</summary>
    sealed class PeInfo
    {
        public static readonly PeInfo Empty = new PeInfo();
        public bool Valid, Is64, IsDll;
        public readonly List<string> Imports = new List<string>();   // DLL names, normal and delay-loaded, each once
        public readonly List<PeExport> Exports = new List<PeExport>();
        public string Pdb;                                            // CodeView (RSDS) PDB path, or null
        public long OverlayOffset;                                    // end of the last section's raw data; 0 = unknown
        public long CertOffset, CertSize;                             // the Authenticode signature (file offset), 0 = none

        /// <summary>Exports that only forward or jump elsewhere (a proxy DLL in front of the real one).</summary>
        public int ForwardedExports => Exports.Count(e => e.Forwarder || e.Stub);
    }

    /// <summary>
    /// Read-only PE parser over bytes: no LoadLibrary, nothing is run. PE32 and PE32+. Reads at most maxRead bytes, seeking to what it needs.
    /// Malformed input gives PeInfo.Empty or what could be read before the problem; it never throws.
    /// </summary>
    static class Pe
    {
        public const long DefaultMaxRead = 8L << 20;
        const int MaxImports = 1024, MaxNames = 4096, MaxStubChecks = 2048;

        public static PeInfo Read(string path, long maxRead = DefaultMaxRead)
        {
            try
            {
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 4096))
                    return Parse(fs, maxRead);
            }
            catch { return PeInfo.Empty; }
        }

        public static PeInfo Parse(Stream s, long maxRead = DefaultMaxRead)
        {
            try { return s == null ? PeInfo.Empty : new Reader(s, maxRead).Parse(); }
            catch { return PeInfo.Empty; }
        }

        sealed class Reader
        {
            struct Section { public uint Va, VSize, Raw, RawSize; }

            readonly Stream s;
            readonly long len;
            long budget;
            Section[] secs = new Section[0];
            uint sizeOfHeaders;

            public Reader(Stream s, long maxRead) { this.s = s; len = s.Length; budget = maxRead; }

            /// <summary>Up to n bytes at a file offset (fewer at the end of the file); null outside the file or over the read cap.</summary>
            byte[] At(long off, int n)
            {
                if (off < 0 || n <= 0 || off >= len) return null;
                n = (int)Math.Min(n, len - off);
                if (n > budget) return null;
                budget -= n;
                s.Position = off;
                var b = new byte[n];
                int r = 0;
                while (r < n) { int k = s.Read(b, r, n - r); if (k <= 0) break; r += k; }
                if (r < n) Array.Resize(ref b, r);
                return b;
            }

            static uint U32(byte[] b, int i) => b != null && i >= 0 && i + 4 <= b.Length ? BitConverter.ToUInt32(b, i) : 0;
            static ushort U16(byte[] b, int i) => b != null && i >= 0 && i + 2 <= b.Length ? BitConverter.ToUInt16(b, i) : (ushort)0;
            static ulong U64(byte[] b, int i) => b != null && i >= 0 && i + 8 <= b.Length ? BitConverter.ToUInt64(b, i) : 0;

            /// <summary>File offset of an RVA, or -1.</summary>
            long Off(uint rva)
            {
                foreach (var x in secs)
                {
                    long size = Math.Max(x.VSize, x.RawSize);
                    if (rva >= x.Va && rva < x.Va + size)
                    {
                        long o = (long)rva - x.Va;
                        return o < x.RawSize ? x.Raw + o : -1;   // in the zero-filled part of the section
                    }
                }
                return rva < sizeOfHeaders ? rva : -1;
            }

            /// <summary>A NUL-terminated printable ASCII name at an RVA (DLL and export names), or null.</summary>
            string Name(uint rva, int max = 256)
            {
                if (rva == 0) return null;
                var b = At(Off(rva), max);
                if (b == null) return null;
                int n = Array.IndexOf(b, (byte)0);
                if (n <= 0) return null;
                for (int i = 0; i < n; i++) if (b[i] < 0x20 || b[i] > 0x7E) return null;
                return Encoding.ASCII.GetString(b, 0, n);
            }

            public PeInfo Parse()
            {
                var dos = At(0, 64);
                if (dos == null || dos.Length < 64 || dos[0] != 'M' || dos[1] != 'Z') return PeInfo.Empty;
                long pe = U32(dos, 0x3C);
                if (pe < 4 || pe > 64 * 1024) return PeInfo.Empty;
                var h = At(pe, 24);
                if (h == null || h.Length < 24 || h[0] != 'P' || h[1] != 'E' || h[2] != 0 || h[3] != 0) return PeInfo.Empty;
                int nsec = U16(h, 6), optSize = U16(h, 20);
                ushort characteristics = U16(h, 22);
                if (nsec == 0 || nsec > 96 || optSize < 96) return PeInfo.Empty;
                var opt = At(pe + 24, optSize);
                if (opt == null || opt.Length < optSize) return PeInfo.Empty;
                ushort magic = U16(opt, 0);
                bool is64 = magic == 0x20b;
                if (!is64 && magic != 0x10b) return PeInfo.Empty;
                ulong imageBase = is64 ? U64(opt, 24) : U32(opt, 28);
                sizeOfHeaders = U32(opt, 60);
                int ddStart = is64 ? 112 : 96;
                uint ndd = U32(opt, is64 ? 108 : 92);
                (uint Rva, uint Size) Dir(int i) => i < ndd && ddStart + i * 8 + 8 <= opt.Length ? (U32(opt, ddStart + i * 8), U32(opt, ddStart + i * 8 + 4)) : (0u, 0u);

                var st = At(pe + 24 + optSize, nsec * 40);
                if (st == null || st.Length < nsec * 40) return PeInfo.Empty;
                secs = new Section[nsec];
                long end = 0;
                for (int i = 0; i < nsec; i++)
                {
                    secs[i] = new Section { VSize = U32(st, i * 40 + 8), Va = U32(st, i * 40 + 12), RawSize = U32(st, i * 40 + 16), Raw = U32(st, i * 40 + 20) };
                    if (secs[i].RawSize > 0) end = Math.Max(end, (long)secs[i].Raw + secs[i].RawSize);
                }
                var info = new PeInfo { Valid = true, Is64 = is64, IsDll = (characteristics & 0x2000) != 0, OverlayOffset = end };
                var cert = Dir(4);   // the security directory holds a file offset, not an RVA
                if (cert.Rva != 0 && cert.Size != 0) { info.CertOffset = cert.Rva; info.CertSize = cert.Size; }
                // each part on its own: a broken export table keeps the imports
                try { Imports(info, Dir(1)); } catch { }
                try { DelayImports(info, Dir(13), imageBase); } catch { }
                try { Exports(info, Dir(0)); } catch { }
                try { Debug(info, Dir(6)); } catch { }
                return info;
            }

            static void AddImport(PeInfo info, string name)
            {
                if (name != null && !info.Imports.Contains(name, StringComparer.OrdinalIgnoreCase)) info.Imports.Add(name);
            }

            void Imports(PeInfo info, (uint Rva, uint Size) d)
            {
                if (d.Rva == 0) return;
                long o = Off(d.Rva);
                if (o < 0) return;
                for (int i = 0; i < MaxImports; i++)
                {
                    var e = At(o + i * 20L, 20);
                    if (e == null || e.Length < 20) break;
                    uint name = U32(e, 12);
                    if (name == 0 && U32(e, 0) == 0 && U32(e, 16) == 0) break;   // the all-zero terminator
                    AddImport(info, Name(name));
                }
            }

            void DelayImports(PeInfo info, (uint Rva, uint Size) d, ulong imageBase)
            {
                if (d.Rva == 0) return;
                long o = Off(d.Rva);
                if (o < 0) return;
                for (int i = 0; i < MaxImports; i++)
                {
                    var e = At(o + i * 32L, 32);
                    if (e == null || e.Length < 32) break;
                    uint attributes = U32(e, 0), name = U32(e, 4);
                    if (name == 0) break;
                    // attribute bit 0 clear: an old (Visual C++ 6) descriptor with virtual addresses instead of RVAs
                    if ((attributes & 1) == 0 && name >= imageBase) name = (uint)(name - imageBase);
                    AddImport(info, Name(name));
                }
            }

            void Exports(PeInfo info, (uint Rva, uint Size) d)
            {
                if (d.Rva == 0) return;
                var e = At(Off(d.Rva), 40);
                if (e == null || e.Length < 40) return;
                uint nfun = U32(e, 20), nnames = U32(e, 24), afun = U32(e, 28), anames = U32(e, 32), aords = U32(e, 36);
                int n = (int)Math.Min(nnames, MaxNames);
                if (n == 0 || nfun == 0) return;
                var names = At(Off(anames), n * 4);
                var ords = At(Off(aords), n * 2);
                var funcs = At(Off(afun), (int)Math.Min(nfun, 65536) * 4);
                if (names == null || ords == null || funcs == null) return;
                for (int i = 0; i < n && i * 4 + 4 <= names.Length && i * 2 + 2 <= ords.Length; i++)
                {
                    var name = Name(U32(names, i * 4));
                    if (name == null) continue;
                    int ord = U16(ords, i * 2);
                    if (ord * 4 + 4 > funcs.Length) continue;
                    uint f = U32(funcs, ord * 4);
                    var x = new PeExport { Name = name };
                    if (f >= d.Rva && f < (long)d.Rva + d.Size) x.ForwardTo = Name(f) ?? "";
                    else if (i < MaxStubChecks) x.Stub = IsStub(f, info.Is64);
                    info.Exports.Add(x);
                }
            }

            /// <summary>The code at an RVA is "jmp [pointer]" (FF 25: x86 absolute, x64 RIP-relative), maybe after up to two E9 jumps.</summary>
            bool IsStub(uint rva, bool is64)
            {
                for (int hop = 0; hop < 3; hop++)
                {
                    var b = At(Off(rva), 8);
                    if (b == null || b.Length < 6) return false;
                    if (b[0] == 0xFF && b[1] == 0x25) return true;
                    if (is64 && b[0] == 0x48 && b[1] == 0xFF && b[2] == 0x25) return true;   // with a REX.W prefix
                    if (b[0] != 0xE9) return false;
                    rva = unchecked((uint)(rva + 5 + BitConverter.ToInt32(b, 1)));
                }
                return false;
            }

            void Debug(PeInfo info, (uint Rva, uint Size) d)
            {
                if (d.Rva == 0) return;
                long o = Off(d.Rva);
                if (o < 0) return;
                int count = (int)Math.Min(d.Size / 28, 16);
                for (int i = 0; i < count; i++)
                {
                    var e = At(o + i * 28L, 28);
                    if (e == null || e.Length < 28) return;
                    if (U32(e, 12) != 2) continue;   // IMAGE_DEBUG_TYPE_CODEVIEW
                    uint size = U32(e, 16), ptr = U32(e, 24);
                    if (size < 25 || ptr == 0) continue;
                    var b = At(ptr, (int)Math.Min(size, 24 + 1024));
                    if (b == null || b.Length < 25 || b[0] != 'R' || b[1] != 'S' || b[2] != 'D' || b[3] != 'S') continue;
                    int end = Array.IndexOf(b, (byte)0, 24);
                    if (end < 0) end = b.Length;
                    if (end > 24) { info.Pdb = Encoding.UTF8.GetString(b, 24, end - 24); return; }
                }
            }
        }
    }
}
