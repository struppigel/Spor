using System.Collections.Generic;
using System.Linq;
using Xunit;

namespace Spor.Tests
{
    /// <summary>FILES lists the files the sections show: Scanner.ShownFiles and Scanner.FilesToList.</summary>
    public class FilesSectionTests
    {
        static HashSet<string> Shown(string[] lines, params string[] keys) => Scanner.ShownFiles(lines, keys);

        [Fact]
        public void FullPathWithBlanksAndParensBeforeStatus()
        {
            var k = @"C:\Program Files (x86)\Some App\app.exe";
            Assert.Contains(k, Shown(new[] { @"2026-11-01 10:00:00 [PF] C:\Program Files (x86)\Some App\app.exe [unsigned] => ran" }, k));
        }

        [Theory]
        [InlineData(@"    dll: C:\Windows\System32\a.dll, C:\Windows\System32\b.dll")]
        [InlineData(@"service x (auto): C:\Windows\System32\b.dll")]
        [InlineData(@"2026-11-01 10:00:00 [PROC] C:\Users\a\x.exe => parent (C:\Windows\System32\b.dll)")]
        [InlineData(@"2026-11-01 10:00:00 [SRU] c:\windows\system32\B.DLL => SRUM")]   // case-insensitive
        public void FullPathAnywhereInALine(string line) =>
            Assert.Contains(@"C:\Windows\System32\b.dll", Shown(new[] { line }, @"C:\Windows\System32\b.dll"));

        [Fact]
        public void ALongerPathIsNotTheFile() =>
            Assert.Empty(Shown(new[] { @"2026-11-01 10:00:00 [NEW] C:\x\a.exe.bak", @"C:\x\a.exe2 => y" }, @"C:\x\a.exe"));

        [Fact]
        public void GroupedFolderWithFilesSubLines()
        {
            var lines = new[]
            {
                @"2026-10-23 22:16:43 [NEW] C:\Users\a\Python\Scripts\ => 3 new files",
                @"    files: f2py.exe, pip.exe",
                @"    files: pip3.exe",
            };
            var s = Shown(lines, @"C:\Users\a\Python\Scripts\pip.exe", @"C:\Users\a\Python\Scripts\pip3.exe", @"C:\Users\a\Python\Scripts\pip3.14.exe");
            Assert.Equal(new[] { @"C:\Users\a\Python\Scripts\pip.exe", @"C:\Users\a\Python\Scripts\pip3.exe" }, s.OrderBy(x => x));
        }

        [Fact]
        public void AFolderOnlyCountsForItsOwnItem()
        {
            var lines = new[]
            {
                @"2026-10-23 22:16:43 [NEW] C:\P\Scripts\ => 1 new file",
                @"    files: a.exe",
                @"2026-10-23 22:16:44 [PF] C:\Q\run.exe => loaded b.exe",
            };
            Assert.Empty(Shown(lines, @"C:\P\Scripts\b.exe"));
        }

        [Theory]
        [InlineData(@"2026-11-12 03:53:25 [PROC] C:\Program Files\x\x.exe [unsigned] => running, pid 5992, parent services.exe")]
        // the folder inside another path is not the folder on its own
        [InlineData(@"2026-11-12 03:53:25 [PROC] C:\Windows\System32\svchost.exe => running, parent services.exe")]
        public void ABareNameIsNotTheFile(string line) =>
            Assert.Empty(Shown(new[] { line }, @"C:\Windows\System32\services.exe"));

        static readonly Dictionary<string, string> Signers = new Dictionary<string, string>
        {
            [@"C:\Windows\System32\drivers\a.sys"] = "valid; signer Microsoft Windows (catalog)",
            [@"C:\Windows\System32\b.dll"] = "valid; signer Microsoft Windows; thumbprint AB",
            [@"C:\Program Files\x\c.exe"] = "unsigned",
            [@"C:\Program Files\x\d.exe"] = "invalid; signer X; note file changed after signing (bad digest)",
            [@"C:\Program Files\x\e.exe"] = "valid; signer X",
        };
        static readonly string[] Keys = Signers.Keys.Concat(new[] { @"C:\Users\a\notes.txt" }).ToArray();   // not an executable: no signer

        static string Signer(string k) => Signers.TryGetValue(k, out var s) ? s : null;

        [Fact]
        public void HiddenValidFilesAreLeftOutAndCounted()
        {
            var shown = new HashSet<string> { @"C:\Program Files\x\e.exe" };
            var (keep, hidden) = Scanner.FilesToList(Keys, Signer, shown, whitelist: true);
            Assert.Equal(2, hidden);   // a.sys, b.dll
            Assert.Equal(new[] { @"C:\Program Files\x\c.exe", @"C:\Program Files\x\d.exe", @"C:\Program Files\x\e.exe", @"C:\Users\a\notes.txt" }, keep);
        }

        [Fact]
        public void WithoutTheWhitelistEverythingIsListed()
        {
            var (keep, hidden) = Scanner.FilesToList(Keys, Signer, new HashSet<string>(), whitelist: false);
            Assert.Equal(0, hidden);
            Assert.Equal(Keys.OrderBy(k => k, System.StringComparer.OrdinalIgnoreCase), keep);
        }
    }
}
