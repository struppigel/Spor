using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Spor.Tests
{
    /// <summary>
    /// Builds minimal PE files in memory for the parser tests: one section at RVA 0x1000 (file offset 0x200) holding the import,
    /// delay-import, export and debug tables and the export code. Nothing here is executable code beyond a few jump bytes.
    /// </summary>
    sealed class PeBuilder
    {
        const uint SectionRva = 0x1000, SectionRaw = 0x200;

        readonly bool is64;
        readonly List<string> imports = new List<string>(), delayImports = new List<string>();
        readonly List<(string Name, string Forward, byte[] Code)> exports = new List<(string, string, byte[])>();
        string pdb;
        byte[] overlay = new byte[0];
        bool dll, cert;

        public PeBuilder(bool is64 = false) { this.is64 = is64; }

        public PeBuilder Import(params string[] names) { imports.AddRange(names); return this; }
        public PeBuilder DelayImport(params string[] names) { delayImports.AddRange(names); return this; }
        public PeBuilder Forwarder(string name, string to) { exports.Add((name, to, null)); return this; }
        public PeBuilder Export(string name, params byte[] code) { exports.Add((name, null, code)); return this; }
        public PeBuilder Pdb(string path) { pdb = path; return this; }
        public PeBuilder Overlay(byte[] bytes) { overlay = bytes; return this; }
        public PeBuilder Dll() { dll = true; return this; }
        public PeBuilder WithCertificate() { cert = true; return this; }

        // section content, addressed by RVA
        readonly List<byte> sec = new List<byte>();
        uint Rva => SectionRva + (uint)sec.Count;
        uint Add(byte[] b) { var r = Rva; sec.AddRange(b); return r; }
        uint AddString(string s) => Add(Encoding.ASCII.GetBytes(s + "\0"));
        uint Reserve(int n) => Add(new byte[n]);
        void Put(uint rva, uint v) { var b = BitConverter.GetBytes(v); for (int i = 0; i < 4; i++) sec[(int)(rva - SectionRva) + i] = b[i]; }
        void Put16(uint rva, ushort v) { var b = BitConverter.GetBytes(v); for (int i = 0; i < 2; i++) sec[(int)(rva - SectionRva) + i] = b[i]; }

        public byte[] Build()
        {
            uint impRva = 0, impSize = 0, delRva = 0, delSize = 0, expRva = 0, expSize = 0, dbgRva = 0;
            if (imports.Count > 0)
            {
                impRva = Reserve(20 * (imports.Count + 1)); impSize = (uint)(20 * (imports.Count + 1));
                for (int i = 0; i < imports.Count; i++) Put(impRva + (uint)(i * 20) + 12, AddString(imports[i]));
            }
            if (delayImports.Count > 0)
            {
                delRva = Reserve(32 * (delayImports.Count + 1)); delSize = (uint)(32 * (delayImports.Count + 1));
                for (int i = 0; i < delayImports.Count; i++)
                {
                    Put(delRva + (uint)(i * 32), 1);   // RVA-based descriptor
                    Put(delRva + (uint)(i * 32) + 4, AddString(delayImports[i]));
                }
            }
            if (exports.Count > 0)
            {
                // directory, function, name and ordinal arrays, names and forwarder strings: all inside the export directory's range
                int n = exports.Count;
                expRva = Reserve(40);
                uint funcs = Reserve(4 * n), names = Reserve(4 * n), ords = Reserve(2 * n);
                Put(expRva + 20, (uint)n); Put(expRva + 24, (uint)n); Put(expRva + 28, funcs); Put(expRva + 32, names); Put(expRva + 36, ords);
                for (int i = 0; i < n; i++)
                {
                    Put(names + (uint)(i * 4), AddString(exports[i].Name));
                    Put16(ords + (uint)(i * 2), (ushort)i);
                    if (exports[i].Forward != null) Put(funcs + (uint)(i * 4), AddString(exports[i].Forward));
                }
                expSize = Rva - expRva;
                for (int i = 0; i < n; i++)
                    if (exports[i].Forward == null)
                    {
                        while (sec.Count % 16 != 0) sec.Add(0xCC);
                        var at = Rva;
                        var code = (byte[])exports[i].Code.Clone();
                        Put(funcs + (uint)(i * 4), Add(code));
                        if (code.Length >= 5 && code[0] == 0xE9 && BitConverter.ToInt32(code, 1) == 0)
                        {
                            // "E9 00000000" in the test data: jump to a FF 25 stub placed right after
                            var target = Add(new byte[] { 0xFF, 0x25, 0, 0, 0, 0, 0xCC, 0xCC });
                            var rel = BitConverter.GetBytes((int)(target - (at + 5)));
                            for (int k = 0; k < 4; k++) sec[(int)(at - SectionRva) + 1 + k] = rel[k];
                        }
                    }
            }
            byte[] rsds = null;
            if (pdb != null)
            {
                dbgRva = Reserve(28);
                var b = new List<byte>(Encoding.ASCII.GetBytes("RSDS")); b.AddRange(new byte[16 + 4]); b.AddRange(Encoding.UTF8.GetBytes(pdb + "\0"));
                rsds = b.ToArray();
                uint rsdsRva = Add(rsds);
                Put(dbgRva + 12, 2); Put(dbgRva + 16, (uint)rsds.Length); Put(dbgRva + 20, rsdsRva); Put(dbgRva + 24, SectionRaw + (rsdsRva - SectionRva));
            }
            while (sec.Count % 0x200 != 0 || sec.Count == 0) sec.Add(0);

            var f = new MemoryStream();
            var w = new BinaryWriter(f);
            // DOS header
            w.Write((byte)'M'); w.Write((byte)'Z'); w.Write(new byte[0x3A]); w.Write(0x40);
            // PE signature, COFF header
            w.Write(Encoding.ASCII.GetBytes("PE\0\0"));
            int optSize = is64 ? 240 : 224;
            w.Write((ushort)(is64 ? 0x8664 : 0x14C)); w.Write((ushort)1); w.Write(0); w.Write(0); w.Write(0); w.Write((ushort)optSize);
            w.Write((ushort)(0x0002 | (dll ? 0x2000 : 0)));
            // optional header
            var opt = new byte[optSize];
            void O16(int at, ushort v) => BitConverter.GetBytes(v).CopyTo(opt, at);
            void O32(int at, uint v) => BitConverter.GetBytes(v).CopyTo(opt, at);
            O16(0, (ushort)(is64 ? 0x20B : 0x10B));
            if (is64) BitConverter.GetBytes(0x140000000UL).CopyTo(opt, 24); else O32(28, 0x400000);
            O32(60, SectionRaw);   // SizeOfHeaders
            int dd = is64 ? 112 : 96;
            O32(is64 ? 108 : 92, 16);
            O32(dd + 0 * 8, expRva); O32(dd + 0 * 8 + 4, expSize);
            O32(dd + 1 * 8, impRva); O32(dd + 1 * 8 + 4, impSize);
            if (pdb != null) { O32(dd + 6 * 8, dbgRva); O32(dd + 6 * 8 + 4, 28); }
            O32(dd + 13 * 8, delRva); O32(dd + 13 * 8 + 4, delSize);
            long certAt = SectionRaw + sec.Count + overlay.Length;
            if (cert) { O32(dd + 4 * 8, (uint)certAt); O32(dd + 4 * 8 + 4, 16); }
            w.Write(opt);
            // section table
            var name = new byte[8]; Encoding.ASCII.GetBytes(".data").CopyTo(name, 0);
            w.Write(name); w.Write((uint)sec.Count); w.Write(SectionRva); w.Write((uint)sec.Count); w.Write(SectionRaw);
            w.Write(new byte[16]);
            while (f.Length < SectionRaw) w.Write((byte)0);
            w.Write(sec.ToArray());
            w.Write(overlay);
            if (cert) w.Write(new byte[16]);
            return f.ToArray();
        }

        public PeInfo Parse() => Pe.Parse(new MemoryStream(Build()));
    }
}
