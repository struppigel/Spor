using System;
using System.IO;
using Xunit;

namespace Spor.Tests
{
    /// <summary>!padded: files inflated with one repeated byte.</summary>
    public class PaddedTests
    {
        static Func<long, int, byte[]> Reader(long length, Func<long, byte> at) => (off, n) =>
        {
            n = (int)Math.Min(n, length - off);
            var b = new byte[n];
            for (int i = 0; i < n; i++) b[i] = at(off + i);
            return b;
        };

        const long Big = 300L << 20;

        [Fact]
        public void Zeros() => Assert.Equal((byte)0, Padded.Check(0, Big, Reader(Big, _ => 0)));

        [Fact]
        public void AnotherRepeatedByte() => Assert.Equal((byte)0xCC, Padded.Check(0, Big, Reader(Big, _ => 0xCC)));

        [Fact]
        public void RealDataIsNotPadded()
        {
            var rnd = new Random(5);
            var data = new byte[1 << 20]; rnd.NextBytes(data);
            Assert.Null(Padded.Check(0, Big, Reader(Big, i => data[i % data.Length])));
        }

        [Fact]
        public void ZerosWithDataAtTheEndAreNot()
        {
            // a big installer with an empty area but real content in the last part
            Assert.Null(Padded.Check(0, Big, Reader(Big, i => i > Big - (1 << 20) ? (byte)(i % 251) : (byte)0)));
        }

        [Fact]
        public void TwoDifferentFillBytesAreNot()
        {
            Assert.Null(Padded.Check(0, Big, Reader(Big, i => i < Big / 2 ? (byte)0 : (byte)0xFF)));
        }

        [Fact]
        public void TooSmallOrUnreadable()
        {
            Assert.Null(Padded.Check(0, 1000, Reader(1000, _ => 0)));
            Assert.Null(Padded.Check(0, Big, (o, n) => null));
        }

        [Theory]
        [InlineData("movie.mkv.crdownload")]
        [InlineData("disk.vdi")]
        [InlineData("disk.vhdx")]
        [InlineData("pagefile.sys")]
        [InlineData("hiberfil.sys")]
        [InlineData("x.part")]
        public void SkippedNames(string name) => Assert.Matches(Padded.Skip, name);

        [Fact]
        public void AZeroFilledDataFileOnDisk()
        {
            var dir = Path.Combine(Path.GetTempPath(), "spor_test_" + Guid.NewGuid().ToString("N").Substring(0, 8));
            Directory.CreateDirectory(dir);
            try
            {
                var f = Path.Combine(dir, "libpython.rpmc");
                using (var fs = new FileStream(f, FileMode.Create)) fs.SetLength(110L << 20);   // zeros, not a sparse file
                Assert.Equal("padded: 110 MB of byte 0x00", Padded.OfFile(new FileInfo(f)));
                var small = Path.Combine(dir, "small.bin");
                using (var fs = new FileStream(small, FileMode.Create)) fs.SetLength(10L << 20);
                Assert.Null(Padded.OfFile(new FileInfo(small)));   // under 100 MB
            }
            finally { Directory.Delete(dir, true); }
        }

        [Fact]
        public void AnInstallerPackageIsCheckedWhole()
        {
            // .msi is a "program" type but not a PE file: no overlay, the whole file counts
            var dir = Path.Combine(Path.GetTempPath(), "spor_test_" + Guid.NewGuid().ToString("N").Substring(0, 8));
            Directory.CreateDirectory(dir);
            try
            {
                var f = Path.Combine(dir, "setup.msi");
                using (var fs = new FileStream(f, FileMode.Create)) fs.SetLength(110L << 20);
                Assert.Equal("padded: 110 MB of byte 0x00", Padded.OfFile(new FileInfo(f)));
            }
            finally { Directory.Delete(dir, true); }
        }

        [Fact]
        public void AnExeWithAZeroOverlayOnDisk()
        {
            var dir = Path.Combine(Path.GetTempPath(), "spor_test_" + Guid.NewGuid().ToString("N").Substring(0, 8));
            Directory.CreateDirectory(dir);
            try
            {
                var f = Path.Combine(dir, "setup.exe");
                File.WriteAllBytes(f, new PeBuilder().Import("KERNEL32.dll").Overlay(new byte[60 << 20]).Build());
                Assert.Equal("padded: 60 MB of byte 0x00", Padded.OfFile(new FileInfo(f)));
                // the same size of real content after the sections is not padding
                var g = Path.Combine(dir, "real.exe");
                var data = new byte[60 << 20]; new Random(9).NextBytes(data);
                File.WriteAllBytes(g, new PeBuilder().Import("KERNEL32.dll").Overlay(data).Build());
                Assert.Null(Padded.OfFile(new FileInfo(g)));
            }
            finally { Directory.Delete(dir, true); }
        }
    }
}
