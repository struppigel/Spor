using System;
using System.Collections.Generic;
using System.Linq;
using Spor.Modules;
using Xunit;

namespace Spor.Tests
{
    /// <summary>Shorter lines: lists on sub-lines, URLs and Defender items on sub-lines, arguments instead of the whole command line, ...</summary>
    public class LineLengthTests
    {
        [Fact]
        public void ChunksNeverCutAName()
        {
            var names = Enumerable.Range(1, 40).Select(i => $"file{i:00}.dll").ToList();
            var parts = Log.Chunks(names, 50);
            Assert.All(parts, p => Assert.True(p.Length <= 50, p));
            Assert.Equal(names, parts.SelectMany(p => p.Split(new[] { ", " }, StringSplitOptions.None)));
        }

        [Fact]
        public void ChunksKeepALongNameWhole()
        {
            var parts = Log.Chunks(new[] { "a.exe", new string('x', 80) + ".dll", "b.exe" }, 50);
            Assert.Equal(new[] { "a.exe", new string('x', 80) + ".dll", "b.exe" }, parts);
        }

        [Fact]
        public void ChunksOfNothing() => Assert.Empty(Log.Chunks(new string[0]));

        [Theory]
        [InlineData(@"C:\a\b.exe --x 1", null, "--x 1")]
        [InlineData(@"""C:\a\b.exe"" --x 1", null, "--x 1")]
        [InlineData(@"c:\A\B.EXE  --x", null, "--x")]             // case does not matter
        [InlineData(@"""C:\a\b.exe""", null, null)]                // no arguments: nothing
        [InlineData(@"C:\a\b.exe", null, null)]
        [InlineData(@"C:\a\bin\..\b.exe --x", @"C:\a\bin\..\b.exe --x", null)]   // another spelling: the whole command line
        [InlineData(@"C:\a\b.exe2 --x", @"C:\a\b.exe2 --x", null)]              // not the program's path
        [InlineData(@"cmd /c start", "cmd /c start", null)]
        [InlineData("", null, null)]
        public void CommandLineOrArguments(string cmd, string commandLine, string args)
        {
            var (cl, a) = Processes.CommandOrArgs(new[] { @"C:\a\b.exe" }, cmd);
            Assert.Equal(commandLine, cl);
            Assert.Equal(args, a);
        }

        [Fact]
        public void BrowserAddressBeatsTheSameZoneUrl()
        {
            var merged = Scanner.MergeMore(new[]
            {
                ("from", "https://cdn.example.com/a.zip?md5=x&expires=1"),   // Zone.Identifier (NEW)
                ("referrer", "https://www.example.com/"),
                ("from", "cdn.example.com/a.zip"),                            // browser history (DL)
                ("page", "www.example.com/mods/124"),
            });
            Assert.Equal(new[] { ("from", "cdn.example.com/a.zip"), ("page", "www.example.com/mods/124"), ("referrer", "https://www.example.com/") }, merged);
        }

        [Fact]
        public void PageOrReferrerThatIsTheDownloadIsLeftOut()
        {
            var merged = Scanner.MergeMore(new[] { ("from", "files.catbox.moe/x.7z"), ("page", "https://files.catbox.moe/x.7z"), ("referrer", "files.catbox.moe/x.7z/") });
            Assert.Equal(new[] { ("from", "files.catbox.moe/x.7z") }, merged);
        }

        [Fact]
        public void OtherSubLinesKeepTheirOrder()
        {
            var merged = Scanner.MergeMore(new[] { ("script", "a"), ("from", "x.com/a"), ("path", "b"), ("from", "x.com/a"), ("script", "a") });
            Assert.Equal(new[] { ("script", "a"), ("from", "x.com/a"), ("path", "b") }, merged);
        }

        [Fact]
        public void DefenderItemsOnePerSubLine()
        {
            var r = Security.Resources(@"F:\x\a.zip; F:\x\b.exe; F:\x\a.zip->c/d.exe");
            Assert.Equal(new[] { ("file", @"F:\x\a.zip"), ("file", @"F:\x\b.exe"), ("file", @"F:\x\a.zip->c/d.exe") }, r);
        }

        [Fact]
        public void DefenderProcessPieceOfTheSamePidIsLeftOut()
        {
            var r = Security.Resources(@"process: C:\u\javaw.exe, pid:24444:119519315058560; pid:24444,ProcessStart:134396139390854349");
            Assert.Equal(new[] { ("process", @"C:\u\javaw.exe, pid:24444:119519315058560") }, r);
        }

        [Fact]
        public void DefenderOtherItems()
        {
            var r = Security.Resources(@"HKLM\SOFTWARE\x; \\server\share\a.exe; pid:7,ProcessStart:1");
            Assert.Equal(new[] { ("resource", @"HKLM\SOFTWARE\x"), ("file", @"\\server\share\a.exe"), ("process", "pid:7,ProcessStart:1") }, r);
        }

        [Fact]
        public void TimestompDetailIsMacb()
        {
            var b = new DateTime(2026, 10, 27, 9, 22, 42, DateTimeKind.Utc);
            var m = b.AddTicks(1234567);
            Assert.Equal("set: B 2026-10-27 09:22:42.0000000, M 2026-10-27 09:22:42.1234567", Timestomp.StpDetail(b, m));
        }

        [Theory]
        [InlineData("x-windowsupdate://E95FFE5A-ED50-446E-A9BE-E11E10927DC4/3DADC9B1/4d65d913", "Windows Update")]
        [InlineData("https://example.com/app.msix", "https://example.com/app.msix")]
        [InlineData("", "")]
        public void WindowsUpdateSource(string src, string shown) => Assert.Equal(shown, Software.Source(src));

        [Fact]
        public void PublishersFileParses()
        {
            var set = Rules.ParsePublishers("# comment\n\nDiscord Inc.\tElectron\r\nGoogle LLC\n  # indented comment\n");
            Assert.Equal(new[] { "Discord Inc.", "Google LLC" }, set.OrderBy(s => s));
            Assert.Contains("discord inc.", set);   // case-insensitive
        }

        [Fact]
        public void BuiltInPublishersAreTheListOfBefore()
        {
            var set = Rules.ParsePublishers(Util.Embedded(Rules.PublishersFile));
            foreach (var s in new[] { "Microsoft Windows", "Microsoft Corporation", "Google LLC", "Discord Inc.", "Valve", "Docker Inc", "Notion Labs, Inc.", "Malwarebytes Inc" })
                Assert.Contains(s, set);
            Assert.Equal(36, set.Count);   // 0.7.2: Malwarebytes Inc and Corporation (native-messaging host of its browser extension)
        }

        [Fact]
        public void FilesEntryIsHashLineAndTwoSubLines()
        {
            var (sig, file, ver) = Scanner.FileParts(
                "valid; signer ASMedia Technology Inc.; thumbprint 7B10E024D9B9F6AA95569BAC2A6A2292E5D2889B; note certificate expired 2022-09-01, timestamped while valid",
                "file version 3.0.5.0000; description AMD GPIO Driver; original name amdgpio3.sys", "A1B2", "541EB09C9F1A0CBACC44CA06B7685523", "33664",
                "2025-12-03 03:33:16", "2025-12-03 03:33:16");
            Assert.Equal("valid; signer ASMedia Technology Inc.; note certificate expired 2022-09-01, timestamped while valid", sig);
            Assert.Equal("md5 541EB09C9F1A0CBACC44CA06B7685523; size 33664; created 2025-12-03 03:33:16; modified 2025-12-03 03:33:16; amcache sha1 A1B2", file);
            Assert.Equal("file version 3.0.5.0000; description AMD GPIO Driver; original name amdgpio3.sys; thumbprint 7B10E024D9B9F6AA95569BAC2A6A2292E5D2889B", ver);
        }

        [Fact]
        public void FilesEntryWithoutVersionOrTimes()
        {
            var (sig, file, ver) = Scanner.FileParts("unsigned", "none", null, null, null, null, null);
            Assert.Equal("unsigned", sig);
            Assert.Null(file);
            Assert.Null(ver);   // no version: line at all
        }

        [Fact]
        public void ElectronIsKnownGoodOnlyWithATrustedValidSignature()
        {
            Signature.Result Sig(string status, string signer) => new Signature.Result { Status = status, Signer = signer };
            Assert.True(Correlate.KnownGoodElectron("Electron", Sig("valid", "Discord Inc.")));
            Assert.True(Correlate.KnownGoodElectron("Electron", Sig("valid", "Microsoft Corporation (catalog)")));
            Assert.False(Correlate.KnownGoodElectron("Electron", Sig("valid", "Black Tree Gaming Ltd")));   // valid, but not well known
            Assert.False(Correlate.KnownGoodElectron("Electron", Sig("expired", "Discord Inc.")));
            Assert.False(Correlate.KnownGoodElectron("Electron", Sig("unsigned", null)));
            Assert.False(Correlate.KnownGoodElectron("Python", Sig("valid", "Discord Inc.")));             // other runtimes are always checked
        }
    }
}
