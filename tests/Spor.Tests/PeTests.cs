using System;
using System.IO;
using System.Linq;
using Xunit;

namespace Spor.Tests
{
    /// <summary>The PE parser on hand-built files: imports, exports, PDB path, overlay; malformed input never throws.</summary>
    public class PeTests
    {
        static readonly byte[] Ret = { 0xC3, 0, 0, 0, 0, 0, 0, 0 };
        static readonly byte[] JmpPtr = { 0xFF, 0x25, 0x10, 0x20, 0, 0, 0xCC, 0xCC };
        static readonly byte[] JmpToStub = { 0xE9, 0, 0, 0, 0, 0xCC, 0xCC, 0xCC };   // the builder points it at a FF 25 stub

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void ImportsNormalAndDelayLoaded(bool is64)
        {
            var pe = new PeBuilder(is64).Import("KERNEL32.dll", "helper.dll").DelayImport("version.dll").Parse();
            Assert.True(pe.Valid);
            Assert.Equal(is64, pe.Is64);
            Assert.Equal(new[] { "KERNEL32.dll", "helper.dll", "version.dll" }, pe.Imports);
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void ExportsForwardersAndJumpStubs(bool is64)
        {
            var pe = new PeBuilder(is64).Dll()
                .Forwarder("Start", "real.Start").Export("Stop", JmpPtr).Export("Pause", JmpToStub).Export("Work", Ret).Parse();
            Assert.True(pe.IsDll);
            Assert.Equal(new[] { "Start", "Stop", "Pause", "Work" }, pe.Exports.Select(e => e.Name));
            Assert.Equal("real.Start", pe.Exports[0].ForwardTo);
            Assert.True(pe.Exports[1].Stub);
            Assert.True(pe.Exports[2].Stub);
            Assert.False(pe.Exports[3].Stub || pe.Exports[3].Forwarder);
            Assert.Equal(3, pe.ForwardedExports);
        }

        [Fact]
        public void PdbPath()
        {
            Assert.Equal(@"D:\build\EventEmitter.pdb", new PeBuilder(true).Pdb(@"D:\build\EventEmitter.pdb").Parse().Pdb);
            Assert.Null(new PeBuilder().Import("a.dll").Parse().Pdb);
        }

        [Fact]
        public void OverlayStartsAfterTheLastSection()
        {
            var bytes = new PeBuilder().Import("a.dll").Overlay(new byte[5000]).Build();
            var pe = Pe.Parse(new MemoryStream(bytes));
            Assert.Equal(bytes.Length - 5000, pe.OverlayOffset);
            Assert.Equal(0, pe.CertOffset);
        }

        [Fact]
        public void CertificateDirectory()
        {
            var bytes = new PeBuilder().Import("a.dll").Overlay(new byte[100]).WithCertificate().Build();
            var pe = Pe.Parse(new MemoryStream(bytes));
            Assert.Equal(bytes.Length - 16, pe.CertOffset);
            Assert.Equal(16, pe.CertSize);
        }

        [Fact]
        public void ReadCapKeepsWhatItCouldRead()
        {
            // headers fit, the rest does not: valid but without tables, no exception
            var pe = Pe.Parse(new MemoryStream(new PeBuilder().Import("a.dll").Build()), maxRead: 600);
            Assert.True(pe.Valid);
        }

        public static TheoryData<byte[]> Malformed()
        {
            var good = new PeBuilder().Import("a.dll").Build();
            var badLfanew = (byte[])good.Clone(); BitConverter.GetBytes(0x7FFFFFF0).CopyTo(badLfanew, 0x3C);
            var badMagic = (byte[])good.Clone(); badMagic[0x40 + 24] = 0x99;
            var badSections = (byte[])good.Clone(); BitConverter.GetBytes((ushort)0).CopyTo(badSections, 0x40 + 6);
            var truncated = good.Take(0x80).ToArray();
            var random = new byte[4096]; new Random(7).NextBytes(random); random[0] = (byte)'M'; random[1] = (byte)'Z';
            return new TheoryData<byte[]> { new byte[0], new byte[] { (byte)'M', (byte)'Z' }, badLfanew, badMagic, badSections, truncated, random };
        }

        [Theory]
        [MemberData(nameof(Malformed))]
        public void MalformedInputIsEmptyAndNeverThrows(byte[] bytes)
        {
            var pe = Pe.Parse(new MemoryStream(bytes));
            Assert.False(pe.Valid);
            Assert.Empty(pe.Imports);
        }

        [Fact]
        public void BrokenTablesKeepTheHeaders()
        {
            // an import directory pointing outside the file: valid, no imports, no exception
            var bytes = new PeBuilder().Import("a.dll").Build();
            int dd = 0x40 + 24 + 96;
            BitConverter.GetBytes(0x7FFF0000u).CopyTo(bytes, dd + 8);
            var pe = Pe.Parse(new MemoryStream(bytes));
            Assert.True(pe.Valid);
            Assert.Empty(pe.Imports);
        }

        [Fact]
        public void MissingFileIsEmpty()
        {
            Assert.False(Pe.Read(@"C:\does\not\exist\x.exe").Valid);
        }
    }
}
