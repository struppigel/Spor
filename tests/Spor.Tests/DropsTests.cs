using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Spor.Modules;
using Xunit;

namespace Spor.Tests
{
    /// <summary>DROP FOLDERS (PavinLoader project folders), LOLBin copies, cached MSI packages and ShimCache times of copies.</summary>
    public class DropsTests
    {
        static List<(string Name, long Size)> Files(params (string, long)[] f) => f.ToList();
        static readonly Func<string, string> NoOrig = _ => null;
        const long MB = 1024 * 1024;

        // ---- Layout ----

        [Theory]
        [InlineData("build.cmd")]
        [InlineData("OneDriveSync.sln")]
        [InlineData("x.csproj.user")]
        [InlineData("Directory.Build.props")]
        [InlineData("MSBuild.exe")]
        [InlineData("DataExportRunner.wsf")]
        public void InACacheFolderOneFileIsEnough(string name) =>
            Assert.NotNull(Drops.Layout(Files((name, 10)), true, NoOrig));

        [Fact]
        public void CacheFoldersOwnFilesAreNoMatch()
        {
            Assert.Null(Drops.Layout(Files(("WebCacheV01.dat", 100), ("thumbcache_256.db", 5), ("x[1].bat", 3)), true, NoOrig));
            Assert.Null(Drops.Layout(Files(), true, NoOrig));
        }

        [Fact]
        public void AVendorFolderNeedsTheWholeLayout()
        {
            Assert.Null(Drops.Layout(Files(("App.sln", 10)), false, NoOrig));
            Assert.Null(Drops.Layout(Files(("App.sln", 10), ("Resources.resx", 4 * MB)), false, NoOrig));   // not over 5 MB
            Assert.Null(Drops.Layout(Files(("MSBuild.exe", 250000)), false, NoOrig));                       // section 2's job
            Assert.Null(Drops.Layout(Files(("x.wsf", 900), ("README.md", 10)), false, NoOrig));
            var r = Drops.Layout(Files(("App.sln", 10), ("App.csproj", 10), ("Resources.resx", 25165824)), false, NoOrig);
            Assert.Equal("project folder (App.sln, App.csproj; Resources.resx 25165824 bytes)", r);
            Assert.NotNull(Drops.Layout(Files(("MSBuild.exe", 250000), ("Helper.wsf", 900)), false, NoOrig));
            Assert.NotNull(Drops.Layout(Files(("App.csproj", 10), ("run.bat", 10)), false, NoOrig));
        }

        [Fact]
        public void MSBuildIsFoundByItsOriginalName()
        {
            var r = Drops.Layout(Files(("HostSvc.exe", 250000), ("Helper.wsf", 900)), false, n => n == "HostSvc.exe" ? "MSBuild.exe" : null);
            Assert.Equal("project folder (HostSvc.exe (MSBuild.exe), Helper.wsf)", r);
        }

        [Fact]
        public void LongListsAreCut()
        {
            var r = Drops.Layout(Files(("MSBuild.exe", 1), ("A.wsf", 1), ("A.sln", 1), ("A.csproj", 1), ("A.targets", 1), ("Defaults.props", 1)), true, NoOrig);
            Assert.Equal("project folder (MSBuild.exe, A.wsf, A.sln, A.csproj, +2 more)", r);
        }

        // ---- groups ----

        static readonly DateTime T0 = new DateTime(2026, 11, 2, 10, 11, 12, DateTimeKind.Utc);

        static Drops.Folder F(string path, double seconds, string reason, string profile = @"C:\Users\anna", params string[] names) =>
            new Drops.Folder { Path = path, Created = T0.AddSeconds(seconds), Reason = reason, Profile = profile,
                               Files = names.Select(n => new Drops.Entry { Name = n }).ToList() };

        static readonly string[] Pavin = { "MSBuild.exe", "X.wsf", "Resources.resx", "X.sln", "X.csproj", "Directory.Build.props", "README.md", "LICENSE" };

        [Fact]
        public void MatchesOfTheSameSecondsAreOneGroupWithTheOldestFirst()
        {
            var a = F(@"C:\Users\anna\AppData\Local\Microsoft\Windows\WebCache\AmqpNet", 0.4, "m", names: Pavin);
            var b = F(@"C:\Users\anna\AppData\Roaming\Microsoft\Protect\RecruitmentTracker", 0.2, "m", names: Pavin);
            var c = F(@"C:\Users\anna\AppData\Local\Microsoft\Windows\WebCache\RecruitmentTracker", 0.9, "m", names: Pavin);
            var later = F(@"C:\Users\anna\AppData\Local\Microsoft\Windows\INetCache\Other", 3600, "m", names: Pavin);
            var groups = Drops.Link(new List<Drops.Folder> { a, b, c, later }, new List<Drops.Folder>());
            Assert.Equal(2, groups.Count);
            Assert.Equal(new[] { b, a, c }, groups[0]);
            Assert.All(groups[0], f => Assert.Same(b, f.Head));
            Assert.Same(later, later.Head);
        }

        [Fact]
        public void FoldersWithTheSameNamesAndFoldersOfTheSameSecondsJoin()
        {
            var m = F(@"C:\Users\anna\AppData\Local\Microsoft\Windows\WebCache\AmqpNet", 0, "m", names: Pavin);
            // MSBuild.exe removed by an antivirus: no match, but 6 of the names
            var sibling = F(@"C:\Users\anna\AppData\Local\Microsoft\Windows\Caches\AmqpNet", 500, null, names: Pavin.Skip(1).ToArray());
            var readmeOnly = F(@"C:\Users\anna\AppData\Roaming\Microsoft\Crypto\Notes", 0, null, names: new[] { "README.md", "LICENSE", "CHANGELOG.md", "CONTRIBUTORS" });
            var near = F(@"C:\Users\anna\AppData\Roaming\Elsewhere", 4, null, names: "X.wsf");
            var inside = F(@"C:\Users\anna\AppData\Local\Microsoft\Windows\WebCache\AmqpNet\obj", 1, null);
            var otherUser = F(@"C:\Users\bob\AppData\Roaming\Elsewhere", 1, null, @"C:\Users\bob", "X.wsf");
            var groups = Drops.Link(new List<Drops.Folder> { m, sibling, readmeOnly }, new List<Drops.Folder> { near, inside, otherUser });
            var g = Assert.Single(groups);
            Assert.Equal(new[] { m, near, sibling }, g);
            Assert.StartsWith(@"same file names as C:\Users\anna\AppData\Local\Microsoft\Windows\WebCache\AmqpNet\ (", sibling.Link);
            Assert.Equal(@"created 4 s after C:\Users\anna\AppData\Local\Microsoft\Windows\WebCache\AmqpNet\", near.Link);
            Assert.Null(readmeOnly.Head);   // shared names, but none a developer or script file
            Assert.Null(inside.Head);       // inside a member
            Assert.Null(otherUser.Head);    // another profile
        }

        [Fact]
        public void RootsCoverEveryProfileTheSystemProfileAndProgramData()
        {
            var r = Drops.Roots(new[] { @"C:\Users\anna" }.Concat(Drops.SystemProfiles(@"C:\Windows")), @"C:\ProgramData");
            Assert.Contains((@"C:\Users\anna\AppData\Local\Microsoft\Windows\WebCache", true, @"C:\Users\anna"), r);
            Assert.Contains((@"C:\Users\anna\AppData\Roaming\Microsoft\Protect", true, @"C:\Users\anna"), r);
            Assert.Contains((@"C:\Users\anna\AppData\Local", false, @"C:\Users\anna"), r);
            Assert.Contains((@"C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\INetCache", true, @"C:\Windows\System32\config\systemprofile"), r);
            Assert.Contains((@"C:\ProgramData\Microsoft\Windows\Caches", true, null), r);
            // every cache folder before the first (big) vendor root: the item cap cuts the vendor folders, not the SYSTEM profile's caches
            Assert.True(r.FindLastIndex(x => x.Cache) < r.FindIndex(x => !x.Cache));
        }

        [Fact]
        public void AGroupKeepsItsFirstFolderFirstAlsoWhenBig()
        {
            var folders = Enumerable.Range(0, 30).Select(i => F(@"C:\Users\anna\AppData\Local\Microsoft\Windows\INetCache\F" + i, 9 - i * 0.3, "m", names: Pavin)).ToList();
            var g = Assert.Single(Drops.Link(folders, new List<Drops.Folder>()));
            var oldest = folders.OrderBy(f => f.Created).First();
            Assert.Same(oldest, g[0]);
            Assert.Equal(g.Skip(1).Select(f => f.Created).OrderBy(t => t), g.Skip(1).Select(f => f.Created));
        }

        // ---- the case: three folders of one drop, the third never ran and is hidden ----

        static readonly string[] Dummies =
        {
            "{0}.sln", "{0}.csproj", "{0}.csproj.user", "{0}.targets", "Directory.Build.props", "Defaults.props", "{0}.Shared.props", "app.config",
            "packages.config", "global.json", "AssemblyInfo.cs", "README.md", "CHANGELOG.md", "CONTRIBUTORS", "LICENSE", "filelist", ".gitattributes",
            ".gitignore", ".gitkeep", "settings_853.cfg", "telemetry_94.dat", "runtime_b9a3.log",
        };

        static void Drop(string dir, string name, byte[] msbuild, bool hidden)
        {
            Directory.CreateDirectory(dir);
            foreach (var d in Dummies) File.WriteAllBytes(Path.Combine(dir, string.Format(d, name)), new byte[0]);
            File.WriteAllText(Path.Combine(dir, name + ".wsf"), "<job><script language=\"JScript\"></script></job>");
            using (var fs = new FileStream(Path.Combine(dir, "Resources.resx"), FileMode.Create)) fs.SetLength(6 * MB);
            File.WriteAllBytes(Path.Combine(dir, "MSBuild.exe"), msbuild);
            if (hidden) File.SetAttributes(dir, File.GetAttributes(dir) | FileAttributes.Hidden);
        }

        [Fact]
        public void TheThirdCopyIsFoundByTheSweepAloneAndAllThreeAreOneGroup()
        {
            var orig = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), @"Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe");
            if (!File.Exists(orig)) orig = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), @"Microsoft.NET\Framework\v4.0.30319\MSBuild.exe");
            if (!File.Exists(orig)) return;   // no .NET Framework MSBuild on this PC
            var bytes = File.ReadAllBytes(orig);
            bytes[bytes.Length / 2] ^= 0xFF;   // one byte changed: the signature no longer holds

            var profile = Path.Combine(Path.GetTempPath(), "spor_test_" + Guid.NewGuid().ToString("N").Substring(0, 8));
            var amqp = Path.Combine(profile, @"AppData\Local\Microsoft\Windows\WebCache\AmqpNet");
            var protect = Path.Combine(profile, @"AppData\Roaming\Microsoft\Protect\RecruitmentTracker");
            var third = Path.Combine(profile, @"AppData\Local\Microsoft\Windows\WebCache\RecruitmentTracker");
            try
            {
                Drop(amqp, "AmqpNet", bytes, false);
                Drop(protect, "RecruitmentTracker", bytes, false);
                Drop(third, "RecruitmentTracker", bytes, true);
                File.WriteAllText(Path.Combine(profile, @"AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat"), "x");   // the cache's own file

                var n = new Drops.Counter();
                var folders = Drops.Sweep(Drops.Roots(new[] { profile }, null), p => Signature.Names(p).Original, n);
                var matches = folders.Where(f => f.Reason != null).ToList();
                Assert.Equal(3, matches.Count);
                Assert.All(matches, f => Assert.StartsWith("project folder (MSBuild.exe, ", f.Reason));
                Assert.All(matches, f => Assert.Contains("Resources.resx 6291456 bytes", f.Reason));

                var near = Drops.Near(profile, matches.Select(f => f.Created).ToList(), new Drops.Counter(), TimeSpan.FromSeconds(10));
                var g = Assert.Single(Drops.Link(folders, near));
                Assert.Equal(3, g.Count(f => f.Reason != null));
                Assert.Contains(g, f => f.Path.Equals(third, StringComparison.OrdinalIgnoreCase) && (f.Attr & FileAttributes.Hidden) != 0);
                Assert.All(g, f => Assert.Same(g[0], f.Head));
                // the parent folders created in the same second are above a member: no members of their own
                Assert.DoesNotContain(g, f => f.Path.EndsWith(@"\WebCache", StringComparison.OrdinalIgnoreCase));

                var sig = Signature.Check(Path.Combine(third, "MSBuild.exe"));
                Assert.Equal("invalid", sig.Status);
                Assert.StartsWith("file changed", sig.Reason);
                Assert.Equal("MSBuild.exe", Signature.Names(Path.Combine(third, "MSBuild.exe")).Original, StringComparer.OrdinalIgnoreCase);
                Assert.Equal("copy of MSBuild.exe outside its usual folders; invalid signature; hidden; in a Windows cache folder",
                             Rules.LolbinCopy(Path.Combine(third, "MSBuild.exe"), "MSBuild.exe", sig.Status, true));
            }
            finally
            {
                try { File.SetAttributes(third, FileAttributes.Directory); } catch { }
                try { Directory.Delete(profile, true); } catch { }
            }
        }

        // ---- LOLBin copies ----

        [Fact]
        public void LolbinsInTheirFoldersAreNoCopies()
        {
            Assert.Null(Rules.LolbinCopy(Rules.SystemDrive + @"\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe", "MSBuild.exe", "valid", false));
            Assert.Null(Rules.LolbinCopy(Rules.SystemDrive + @"\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe", "MSBuild.exe", "valid", false));
            Assert.Null(Rules.LolbinCopy(Rules.SystemDrive + @"\Windows\System32\wscript.exe", "wscript.exe", "valid", false));
            Assert.Null(Rules.LolbinCopy(Rules.SystemDrive + @"\Windows\SysWOW64\mshta.exe", "MSHTA.EXE", "valid", false));
            Assert.Null(Rules.LolbinCopy(Rules.SystemDrive + @"\Windows\Microsoft.NET\Framework\v4.0.30319\RegAsm.exe", "RegAsm.exe", "valid", false));
        }

        [Fact]
        public void ACopyElsewhereIsOne()
        {
            Assert.Equal("copy of MSBuild.exe outside its usual folders; invalid signature; in a Windows cache folder",
                         Rules.LolbinCopy(@"C:\Users\anna\AppData\Local\Microsoft\Windows\WebCache\AmqpNet\MSBuild.exe", "MSBuild.exe", "invalid", false));
            Assert.Equal("copy of RegAsm.exe outside its usual folders (named svc.exe)",
                         Rules.LolbinCopy(@"C:\Users\anna\AppData\Roaming\8e9279a59036\svc.exe", "RegAsm.exe", "valid", false));   // validly signed, but in AppData
            Assert.Equal("copy of wscript.exe outside its usual folders; unsigned; hidden",
                         Rules.LolbinCopy(@"D:\Windows\System32\wscript.exe", null, "unsigned", true));   // System32 counts only on the system drive
            Assert.NotNull(Rules.LolbinCopy(@"C:\Users\anna\AppData\Local\AVerMedia\Stream Engine Service\MSBuild.exe", null, null, false));   // gone: by name
        }

        [Fact]
        public void VisualStudioOnAnotherDriveCountsWhenValidlySigned()
        {
            var other = Rules.SystemDrive.Equals("D:", StringComparison.OrdinalIgnoreCase) ? "E:" : "D:";
            var vs = other + @"\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\amd64\MSBuild.exe";
            Assert.Null(Rules.LolbinCopy(vs, "MSBuild.exe", "valid", false));
            Assert.NotNull(Rules.LolbinCopy(vs, "MSBuild.exe", "invalid", false));
        }

        [Fact]
        public void AValidCopyInProgramFilesAndOtherProgramsAreNoFinding()
        {
            Assert.Null(Rules.LolbinCopy(Rules.SystemDrive + @"\Program Files\JetBrains\Rider\tools\MSBuild.exe", "MSBuild.exe", "valid", false));
            Assert.NotNull(Rules.LolbinCopy(Rules.SystemDrive + @"\Program Files\JetBrains\Rider\tools\MSBuild.exe", "MSBuild.exe", "invalid", false));
            Assert.Null(Rules.LolbinCopy(@"C:\Users\anna\AppData\Local\x\notepad.exe", "NOTEPAD.EXE", "valid", false));
            Assert.Null(Rules.LolbinCopy(@"C:\Users\anna\AppData\Local\x\powershell.exe", "PowerShell.EXE", "valid", false));   // not one of the nine
        }

        [Fact]
        public void TheSystemProfilesAppDataIsNoTrustedLocation() =>
            Assert.False(Rules.InTrustedLocation(Rules.SystemDrive + @"\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\INetCache\X\MSBuild.exe"));

        // ---- cached MSI packages ----

        static readonly List<string[]> RenDirs = new List<string[]>
        {
            new[] { "TARGETDIR", "", "SourceDir" },
            new[] { "LocalAppDataFolder", "TARGETDIR", "." },
            new[] { "VendorDir", "LocalAppDataFolder", "Realtek" },
            new[] { "INSTALLFOLDER", "VendorDir", "CARDRE~1|Card Reader Helper" },
        };
        static readonly List<string[]> RenFiles = new List<string[]> { new[] { "helper_wsf", "helper.wsf|Helper.wsf" }, new[] { "app_exe", "App.exe" } };

        [Fact]
        public void AScriptActionIntoLocalAppDataIsFlagged()
        {
            var actions = new List<string[]> { new[] { "LaunchHelper", "3106", "INSTALLFOLDER", "wscript.exe //B //NoLogo \"[#helper_wsf]\"" } };
            var hit = Software.MsiSuspicious(actions, RenDirs, RenFiles);
            Assert.NotNull(hit);
            Assert.Equal(new[] { @"Realtek\Card Reader Helper" }, hit.Folders);
            Assert.Equal("LaunchHelper: INSTALLFOLDER wscript.exe //B //NoLogo \"[Helper.wsf]\"", Assert.Single(hit.Actions));
        }

        [Fact]
        public void AnOwnScriptOrAScriptActionFromAFileCountsToo()
        {
            Assert.NotNull(Software.MsiSuspicious(new List<string[]> { new[] { "Run", "18", "app_exe", "\"[#helper_wsf]\"" } }, RenDirs, RenFiles));
            Assert.NotNull(Software.MsiSuspicious(new List<string[]> { new[] { "Run", "1046", "helper_wsf", "" } }, RenDirs, RenFiles));   // 22 = VBScript from a file
            Assert.NotNull(Software.MsiSuspicious(new List<string[]> { new[] { "Run", "51", "WixQuietExecCmdLine", "\"powershell.exe\" -ep bypass -f x.ps1" } }, RenDirs, RenFiles));
            // a folder property in front of the host, as MSI writes it
            Assert.NotNull(Software.MsiSuspicious(new List<string[]> { new[] { "Run", "34", "INSTALLFOLDER", "\"[SystemFolder]cmd.exe\" /c start wscript //b x.wsf" } }, RenDirs, RenFiles));
            Assert.NotNull(Software.MsiSuspicious(new List<string[]> { new[] { "Run", "34", "INSTALLFOLDER", "[SystemFolder]wscript.exe //b x.vbs" } }, RenDirs, RenFiles));
        }

        [Fact]
        public void OtherPackagesAreNot()
        {
            var actions = new List<string[]> { new[] { "LaunchHelper", "3106", "INSTALLFOLDER", "wscript.exe //B \"[#helper_wsf]\"" } };
            var pf = new List<string[]> { new[] { "TARGETDIR", "", "SourceDir" }, new[] { "ProgramFilesFolder", "TARGETDIR", "." }, new[] { "INSTALLFOLDER", "ProgramFilesFolder", "Realtek" } };
            Assert.Null(Software.MsiSuspicious(actions, pf, RenFiles));                                                                          // Program Files
            Assert.Null(Software.MsiSuspicious(new List<string[]> { new[] { "Launch", "226", "INSTALLFOLDER", "\"[#app_exe]\" /start" } }, RenDirs, RenFiles));   // runs its program
            Assert.Null(Software.MsiSuspicious(new List<string[]> { new[] { "SetDir", "35", "INSTALLFOLDER", "[LocalAppDataFolder]cmd" } }, RenDirs, RenFiles)); // sets a folder
            Assert.Null(Software.MsiSuspicious(new List<string[]>(), RenDirs, RenFiles));
        }

        // ---- ShimCache times of copies ----

        static readonly DateTime July = new DateTime(2026, 7, 5, 8, 0, 0, DateTimeKind.Utc);
        static readonly DateTime Nov = new DateTime(2026, 11, 2, 10, 11, 12, DateTimeKind.Utc);
        const string Copy = @"C:\Users\anna\AppData\Local\Microsoft\Windows\WebCache\AmqpNet\MSBuild.exe";

        [Fact]
        public void ACopiedFilesShimCacheTimeBecomesADetailOfItsLaterEvidence()
        {
            var sc = new TEvent { T = July, Src = "SC", Path = Copy };
            var am = new TEvent { T = Nov.AddMinutes(5), Src = "AM", Path = Copy.ToUpperInvariant() };
            var sru = new TEvent { T = Nov.AddMinutes(60), Src = "SRU", Path = Copy };
            var events = new List<TEvent> { sc, am, sru };
            var keep = Correlate.FoldCopiedShimCache(events, new List<(DateTime?, string)>(), _ => Nov);
            Assert.Empty(keep);
            Assert.Equal(new[] { am, sru }, events);
            Assert.Equal(("shimcache", "file modified 2026-07-05 08:00:00 " + Correlate.CopiedNote), Assert.Single(am.More));
            Assert.Null(sru.More);
        }

        [Fact]
        public void APendingFindingOfACopyIsFoldedOthersStay()
        {
            var am = new TEvent { T = Nov, Src = "AM", Path = Copy };
            var events = new List<TEvent> { am };
            var pending = new List<(DateTime?, string)> { (July, Copy), (July, @"C:\Users\anna\Old\x.exe"), (July, null) };
            Assert.Equal(new[] { 1, 2 }, Correlate.FoldCopiedShimCache(events, pending, _ => Nov));
            Assert.Single(am.More);
        }

        [Fact]
        public void WithoutProofOfACopyOrOtherEvidenceNothingChanges()
        {
            var sc = new TEvent { T = July, Src = "SC", Path = Copy };
            var pf = new TEvent { T = Nov, Src = "PF", Path = Copy };
            var events = new List<TEvent> { sc, pf };
            Assert.Empty(Correlate.FoldCopiedShimCache(events, new List<(DateTime?, string)>(), _ => July.AddSeconds(1)));   // created with its time
            Assert.Equal(2, events.Count);
            Assert.Empty(Correlate.FoldCopiedShimCache(events, new List<(DateTime?, string)>(), _ => null));                 // gone: no proof
            Assert.Equal(2, events.Count);
            var alone = new List<TEvent> { new TEvent { T = July, Src = "SC", Path = Copy } };
            Assert.Equal(new[] { 0 }, Correlate.FoldCopiedShimCache(alone, new List<(DateTime?, string)> { (July, Copy) }, _ => Nov));   // no other evidence
            Assert.Single(alone);
        }
    }
}
