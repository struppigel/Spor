using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using Xunit;

namespace Spor.Tests
{
    /// <summary>Autodetect: the built-in known-malware database, its matcher and its speed.</summary>
    public class AutodetectTests
    {
        static readonly Autodetect.Db Db = Autodetect.Parse(Autodetect.Embedded());

        static List<string> Families(string kind, string value) => Db.Match(kind, value).Select(p => p.Family).Distinct().ToList();

        [Fact]
        public void TheBuiltInDatabaseLoadsWithoutErrors()
        {
            Assert.Empty(Db.Errors);
            Assert.True(Db.Patterns.Count > 150, $"only {Db.Patterns.Count} rows");
        }

        [Fact]
        public void EveryRowMatchesItsOwnExample()
        {
            // the example is a value as Spor sees it: proof that the FenrisHub rule was rewritten for Spor
            var bad = Db.Patterns.Where(p => !Db.Match(p.Kind, p.Example).Contains(p)).Select(p => p.ToString()).ToList();
            Assert.Empty(bad);
        }

        [Fact]
        public void EveryKeyIsInItsExample()
        {
            var bad = Db.Patterns.Where(p => p.Literal != null && !p.Example.ToLowerInvariant().Contains(p.Literal)
                                             && !(p.Kind == "domain" && p.Op == '=')).Select(p => p.ToString()).ToList();
            Assert.Empty(bad);
        }

        [Fact]
        public void EveryRowNamesItsFamilyAndFenrisRules()
        {
            Assert.All(Db.Patterns, p => Assert.False(string.IsNullOrWhiteSpace(p.Family), p.ToString()));
            Assert.All(Db.Patterns, p => Assert.Matches(@"^\d+(,\d+)*$", p.Ids));
        }

        [Theory]
        [InlineData("path", @"C:\Users\anna\AppData\Local\Temp\tmp-20656-vmkfjqTWAOFi\ehyISWlPN.exe", "RenLoader")]
        [InlineData("path", @"C:\Users\anna\Downloads\tmp-39304-wscJmiyovbGx", "RenLoader")]
        [InlineData("path", @"C:\ProgramData\com_usr_node_v9\OvSupervisor.exe", "RenLoader")]
        [InlineData("path", @"C:\Users\anna\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\StackBroker_win64.lnk", "RenLoader")]
        [InlineData("path", @"C:\ProgramData\68c1b467a2d\nss3.dll", "Vidar")]
        [InlineData("path", @"C:\Windows\Pluton\722898\PlutonAgent.exe", "Fake Windows folders")]
        [InlineData("task", @"\YandexUpdateService{26F2-FCC3-AFD6-CF40-B4E714805533ACC}", "CountLoader")]
        [InlineData("task", @"\Helix Jordan 58776-S-1-5-21-2276490796-40676578-3919172078-1000", "RenLoader")]
        [InlineData("task", @"\SearchIndexer", "PavinLoader")]
        [InlineData("software", "Lighting Control Agent | 3.1 | Corsair Components Inc.", "RenLoader")]
        [InlineData("software", "DxQMWkyuwv hVZ6WPEG | 4.8.1858 | h3bJF3rjJ", "LegionLoader")]
        [InlineData("domain", "cdn.snconor.vg", "CountLoader")]
        [InlineData("cmd", @"C:\WINDOWS\system32\conhost.exe --headless mshta.exe https://snconor.vg", "CountLoader")]
        [InlineData("company", "valid; signer Lupus Tech Limited; thumbprint AB", "TamperedChef")]
        [InlineData("service", "u234944", "Coinminer")]
        [InlineData("run", "BuilderBeta", "RenLoader")]
        public void KnownMalware(string kind, string value, string family) => Assert.Contains(family, Families(kind, value));

        [Theory]
        // the lab tooling of the RenLoader test VM and common software: nothing
        [InlineData("path", @"C:\Users\richa\Desktop\tools\x64dbg\release\x64\x64dbg.exe")]
        [InlineData("path", @"C:\Users\richa\AppData\Local\Programs\Python\Python313\python.exe")]
        [InlineData("path", @"C:\Program Files\nodejs\node.exe")]
        [InlineData("path", @"C:\Windows\System32\VBoxService.exe")]
        [InlineData("path", @"C:\Users\anna\AppData\Local\Temp\tmp-12345-abcdefghijkl\node_modules\x\index.js")]   // Node's tmp package, no program
        [InlineData("path", @"C:\Program Files\Corsair\CORSAIR iCUE 5 Software\iCUE.exe")]
        [InlineData("path", @"C:\Program Files\Google\Chrome\Application\chrome.exe")]
        [InlineData("path", @"C:\ProgramData\Package Cache\{3B5A8B3E-1F2C-4C0E-9C7B-6F0E3D1E2A11}\setup.exe")]
        [InlineData("path", @"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24090.11-0\MsMpEng.exe")]
        [InlineData("path", @"C:\Users\anna\Downloads\setup (1).exe")]
        [InlineData("path", @"C:\Users\anna\AppData\Local\Microsoft\Windows\INetCache\IE\ABCD1234\setup[1].exe")]
        [InlineData("task", @"\GoogleUpdateTaskMachineCore{6D4F1EAA-5C3B-4C3B-9F3E-1A2B3C4D5E6F}")]   // a GUID, not 4-4-4-4-15
        [InlineData("task", @"\OneDrive Standalone Update Task-S-1-5-21-1111111111-2222222222-3333333333-1001")]
        [InlineData("task", @"\Microsoft\Windows\UpdateOrchestrator\Schedule Scan")]
        [InlineData("task", @"\Intel PTT EK Recertification")]
        [InlineData("software", "NVIDIA GPX Common OSS binaries (POCO, OpenSSL, libprotobuf) | 7.1 | NVIDIA Corporation")]
        [InlineData("software", "Realtek Audio Driver | 6.0.9235.1 | Realtek Semiconductor Corp.")]
        [InlineData("software", "Wireshark Portable | 1.0 | Wireshark")]
        [InlineData("software", "TeamViewer | 15.50.5 | TeamViewer")]
        [InlineData("domain", "snconor.vg.example.com")]
        [InlineData("domain", "notsnconor.vg")]
        [InlineData("company", "valid; signer Microsoft Corporation; company Microsoft Corporation")]
        [InlineData("service", "wuauserv")]
        [InlineData("run", "OneDrive")]
        [InlineData("cmd", @"C:\Windows\System32\mshta.exe ""C:\Program Files\App\help.hta""")]
        public void CleanValues(string kind, string value) => Assert.Empty(Families(kind, value));

        [Fact]
        public void TheRenLoaderLabRunIsNamed()
        {
            // Spor030_jovialsnatcher.txt: the payload, its DLLs and the dropper task
            Assert.Contains("RenLoader", Families("path", @"C:\Users\richa\AppData\Local\Temp\tmp-20656-vmkfjqTWAOFi\ehyISWlPN.exe"));
            Assert.Empty(Families("task", @"\JovialRun"));   // a name of this lab sample only
        }

        [Fact]
        public void AHitIsAtItsEarliestExactTime()
        {
            // the lab run: file created 03:33:50, process started 03:33:52, SRUM hour bucket 03:54:00
            DateTime T(int h, int m, int s) => new DateTime(2026, 11, 20, h, m, s, DateTimeKind.Utc);
            Assert.Equal(T(3, 33, 50), Autodetect.When(new (DateTime?, bool)[] { (T(3, 54, 0), true), (T(3, 33, 52), false), (null, false), (T(3, 33, 50), false) }));
            // an exact time wins over a SRUM bucket, even an earlier one: the bucket is only the hour SRUM wrote its record
            Assert.Equal(T(3, 33, 52), Autodetect.When(new (DateTime?, bool)[] { (T(3, 0, 0), true), (T(3, 33, 52), false) }));
            // only buckets: the earliest one; no time at all: none
            Assert.Equal(T(3, 54, 0), Autodetect.When(new (DateTime?, bool)[] { (T(4, 54, 0), true), (T(3, 54, 0), true), (null, false) }));
            Assert.Null(Autodetect.When(new (DateTime?, bool)[] { (null, false) }));
        }

        [Fact]
        public void AFileHitMarksItsTimelineEvents()
        {
            var at = new DateTime(2026, 11, 20, 3, 33, 52, DateTimeKind.Utc);
            var shared = new List<string> { "!motw-removed" };   // modules may pass one list to several events
            var events = new List<TEvent>
            {
                new TEvent { T = at, Src = "PROC", Path = @"C:\Users\richa\AppData\Local\Temp\tmp-20656-vmkfjqTWAOFi\ehyISWlPN.exe", Flags = shared },
                new TEvent { T = at, Src = "NEW", Path = @"c:\users\richa\appdata\local\temp\TMP-20656-vmkfjqTWAOFi\ehyISWlPN.exe", Extra = "zone 0" },
                new TEvent { T = at, Src = "NEW", Path = @"C:\Users\richa\AppData\Local\Temp\tmp-20656-vmkfjqTWAOFi\ETWProviders.dll", Flags = shared },
                new TEvent { T = at, Src = "RUN", Text = "Run dialog: cmd" },
            };
            var path = @"C:\Users\richa\AppData\Local\Temp\tmp-20656-vmkfjqTWAOFi\ehyISWlPN.exe";
            Assert.True(Autodetect.Mark(events, path, "RenLoader", "payload in a Node.js tmp folder"));
            Assert.True(Autodetect.Mark(events, path, "RenLoader", "payload in a Node.js tmp folder"));   // twice: once only
            Assert.Equal(new[] { "!motw-removed", Autodetect.Flag }, events[0].Flags);
            Assert.Equal(new[] { Autodetect.Flag }, events[1].Flags);
            Assert.Equal("known malware RenLoader: payload in a Node.js tmp folder", events[0].Known);
            Assert.Equal("known malware RenLoader: payload in a Node.js tmp folder", events[1].Known);
            Assert.Equal("zone 0", events[1].Extra);
            // other files and text events untouched, and the shared flag list too
            Assert.Equal(new[] { "!motw-removed" }, events[2].Flags);
            Assert.Null(events[2].Known);
            Assert.Null(events[3].Flags);
            Assert.False(Autodetect.Mark(events, @"C:\elsewhere\x.exe", "F", ""));
        }

        [Theory]
        [InlineData("path\t=abc\tF", "needs at least 5")]
        [InlineData("nope\t=abc\tF\tn\tabc", "unknown kind")]
        [InlineData("path\t=ab\tF\tn\tab", "at least 3 characters")]
        [InlineData("path\t/(/ key=abc\tF\tn\tabc", "bad regex")]
        [InlineData("path\t/abc/\tF\tn\tabc", "without a key only for")]
        [InlineData("path\tabc\tF\tn\tabc", "must start with")]
        public void BadRowsAreReported(string row, string why)
        {
            var d = Autodetect.Parse(row);
            Assert.Empty(d.Patterns);
            Assert.Contains(d.Errors, e => e.Contains(why));
        }

        [Fact]
        public void ARegexWithoutKeyRunsOnEveryValueOfASmallKind()
        {
            var d = Autodetect.Parse("task\t/^\\\\a\\d+$/\tF\tn\t\\a1\t1");
            Assert.Empty(d.Errors);
            Assert.Single(d.Match("task", @"\a42"));
            Assert.Empty(d.Match("task", @"\b42"));
        }

        [Fact]
        public void ADomainRowAlsoMatchesCommandLines()
        {
            var d = Autodetect.Parse("domain\t=evil.vg\tF\tn\tevil.vg\t1");
            Assert.Single(d.Match("domain", "a.b.evil.vg"));
            Assert.Single(d.Match("cmd", "mshta https://evil.vg/x"));
            Assert.Empty(d.Match("domain", "evil.vg.example"));
        }

        [Theory]
        [InlineData(@"C:\x\y.dll [unsigned] (side-loaded)", @"C:\x\y.dll")]
        [InlineData(@"C:\Program Files (x86)\App\app.exe => details", @"C:\Program Files (x86)\App\app.exe")]
        [InlineData(@"C:\Users\anna\Downloads\setup (1).exe", @"C:\Users\anna\Downloads\setup (1).exe")]
        [InlineData(@"C:\Windows\System32\svc.dll (svchost DLL)", @"C:\Windows\System32\svc.dll")]
        [InlineData(@"C:\a\b.exe  !lolbin", @"C:\a\b.exe")]
        [InlineData("author WINDOWS10\\richa", null)]
        public void PathOfSubLineValues(string value, string path) => Assert.Equal(path, Autodetect.PathOf(value));

        [Fact]
        public void AhoCorasickFindsWhatIndexOfFinds()
        {
            var rnd = new Random(7);
            string Word(int n) => new string(Enumerable.Range(0, n).Select(_ => "abc\\._"[rnd.Next(6)]).ToArray());
            var words = Enumerable.Range(0, 60).Select(i => Word(2 + rnd.Next(5))).Distinct().ToList();
            var ac = new AhoCorasick<string>();
            foreach (var w in words) ac.Add(w, w);
            ac.Build();
            for (int i = 0; i < 2000; i++)
            {
                var text = Word(rnd.Next(40));
                var expected = words.Where(w => text.IndexOf(w, StringComparison.Ordinal) >= 0).OrderBy(w => w).ToList();
                Assert.Equal(expected, ac.Find(text).OrderBy(w => w).ToList());
            }
        }

        [Fact]
        public void FiftyThousandPathsInWellUnderASecond()
        {
            var rnd = new Random(1);
            var dirs = new[] { @"C:\Program Files\Vendor", @"C:\ProgramData\Microsoft\Windows", @"C:\Users\anna\AppData\Local\Temp", @"C:\Users\anna\AppData\Roaming\Microsoft\Windows",
                               @"C:\Windows\System32", @"C:\Users\anna\AppData\Local\Microsoft\Windows\INetCache\IE", @"C:\Users\anna\Downloads" };
            var paths = Enumerable.Range(0, 50000).Select(i => $@"{dirs[i % dirs.Length]}\sub{rnd.Next(500)}\file_{i}.{(i % 3 == 0 ? "exe" : "dll")}").ToList();
            var d = Autodetect.Parse(Autodetect.Embedded());
            d.Match("path", paths[0]);   // first use builds the regexes it needs
            var sw = Stopwatch.StartNew();
            int hits = paths.Sum(p => d.Match("path", p).Count);
            sw.Stop();
            Assert.True(sw.Elapsed.TotalSeconds < 1.0, $"{sw.Elapsed.TotalSeconds:N2} s for 50000 paths");
            Assert.Equal(0, hits);
        }
    }
}
