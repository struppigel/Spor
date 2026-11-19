using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Threading;
using Xunit;

namespace Spor.Tests
{
    /// <summary>The line format of docs/LOG-FORMAT.md, as Log and Table write it.</summary>
    public class LogFormatTests
    {
        const string Time = "2026-11-19 21:09:24";

        static List<string> Written(Table table)
        {
            var log = new Log();
            table.WriteTo(log);
            // "(line: ...)" and an empty line come first, then the items.
            Assert.StartsWith("(line: ", log.Lines[0]);
            Assert.Equal("", log.Lines[1]);
            return log.Lines.Skip(2).ToList();
        }

        [Fact]
        public void TargetGetsTheStatusAndTheDetailsAfterAComma()
        {
            var t = new Table("@time", "[kind", "*entry", ">program", "!status", "arguments", "value", "<flags");
            t.Add(Time, "run", @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\X", @"C:\x\a.exe", "unsigned", "-a", "X", "!lolbin");
            Assert.Equal(new[] { Time + @" [run] HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\X => C:\x\a.exe [unsigned], arguments -a; value X <==== !lolbin" },
                         Written(t));
        }

        [Fact]
        public void WithoutATargetTheStatusFollowsTheItem()
        {
            var t = new Table("@time", "[kind", "*entry", ">program", "!status", "arguments", "value", "<flags");
            t.Add(Time, "run", @"HKLM\...\Run\X", "-", "gone", "-a", "X", null);
            Assert.Equal(new[] { Time + @" [run] HKLM\...\Run\X [gone] => arguments -a; value X" }, Written(t));
        }

        [Fact]
        public void EmptyAndDashFieldsAreLeftOut()
        {
            var t = new Table("@time", "[sources", "*file", "!status", "=details", "<flags");
            t.Add(null, "-", @"C:\x\a.exe", "", "-", null);
            Assert.Equal(new[] { @"C:\x\a.exe" }, Written(t));
        }

        [Fact]
        public void EachTagColumnIsItsOwnBracket()
        {
            var t = new Table("@time", "[user", "[browser", "*file");
            t.Add(Time, "anna", "Brave", @"C:\Users\anna\Downloads\x.zip");
            t.Add(Time, null, "Brave", @"C:\Users\bob\Downloads\y.zip");
            Assert.Equal(new[]
            {
                Time + @" [anna] [Brave] C:\Users\anna\Downloads\x.zip",
                Time + @" [Brave] C:\Users\bob\Downloads\y.zip",
            }, Written(t));
        }

        [Fact]
        public void SubLinesAreIndentedFourSpaces()
        {
            var t = new Table("@time", "[browser", "*file");
            t.Add(Time, "Brave", @"C:\x\a.zip");
            t.More("from", "https://example.com/a.zip");
            t.More("page", "");   // empty values are left out
            Assert.Equal(new[] { Time + @" [Brave] C:\x\a.zip", "    from: https://example.com/a.zip" }, Written(t));
        }

        [Fact]
        public void HeadingIsOneHundredWideWithAtLeastFourEquals()
        {
            var log = new Log();
            log.Heading("TIMELINE - last 30 days, oldest first");
            log.Heading("EXECUTION EVIDENCE - PCA, UserAssist, BAM, ShimCache, Compatibility Assistant and some more words");
            Assert.Equal(100, log.Lines[0].Length);
            Assert.StartsWith("==================== TIMELINE - last 30 days, oldest first ====", log.Lines[0]);
            Assert.EndsWith(" ====", log.Lines[1]);
        }

        [Fact]
        public void ItemInsideALine()
        {
            Assert.Equal(@"C:\a.exe [unsigned] => x <==== !f", Log.Item(@"C:\a.exe", "unsigned", "x", "!f"));
            Assert.Equal(@"C:\a.exe", Log.Item(@"C:\a.exe", "-", null, ""));
        }

        public static IEnumerable<object[]> ModuleLines()
        {
            // Column sets the modules use, with the item each line must split into.
            yield return new object[] { new[] { "@time", "[sources", "*file or event", "!status", "=details", "<flags" },
                new[] { Time, "PF PCA BAM", @"C:\Users\Bob\evil.exe", "unsigned", "PCA: launched", "!double-extension" },
                @"C:\Users\Bob\evil.exe", new[] { "!double-extension" } };
            yield return new object[] { new[] { "@time", "[kind", "*entry", ">program", "!status", "start", "<flags" },
                new[] { Time, "service", "EvilSvc", @"C:\x\evil.exe", "invalid signature", "auto", "" },
                "EvilSvc", new string[0] };
            yield return new object[] { new[] { "*file", ">sha256", "signature", "=version", "amcache sha1", "md5", "size", "created", "modified" },
                new[] { @"C:\x\a.exe", new string('A', 64), "valid; signer X", "file version 1.0", "-", new string('B', 32), "10", Time, Time },
                @"C:\x\a.exe", new string[0] };
            yield return new object[] { new[] { "@time", "[user", "[browser", "!status", "<flags", "*file" },
                new[] { Time, "anna", "Brave", "> 500 MB, not hashed, unsigned", "!kept-despite-warning", @"C:\Users\anna\big.iso" },
                @"C:\Users\anna\big.iso", new[] { "!kept-despite-warning" } };
        }

        /// <summary>LOG-FORMAT.md, "How to split a line": the first 19 characters are the time, "&lt;==== " splits
        /// off the flags, the first " =&gt; " splits the item from the rest.</summary>
        [Theory]
        [MemberData(nameof(ModuleLines))]
        public void LinesSplitByTheDocumentedRules(string[] columns, string[] values, string item, string[] flags)
        {
            var t = new Table(columns);
            t.Add(values);
            var line = Written(t).Single();
            var rest = line;
            if (char.IsDigit(line[0]))
            {
                Assert.True(DateTime.TryParseExact(line.Substring(0, 19), Log.TimeFmt, CultureInfo.InvariantCulture, DateTimeStyles.None, out _));
                rest = line.Substring(20);
            }
            var cut = rest.IndexOf(" <==== ", StringComparison.Ordinal);
            Assert.Equal(flags, cut < 0 ? new string[0] : rest.Substring(cut + 7).Split(' '));
            if (cut >= 0) rest = rest.Substring(0, cut);
            while (rest.StartsWith("[")) rest = rest.Substring(rest.IndexOf("] ", StringComparison.Ordinal) + 2);
            var arrow = rest.IndexOf(" => ", StringComparison.Ordinal);
            var head = arrow < 0 ? rest : rest.Substring(0, arrow);
            Assert.Equal(item, Status.Replace(head, ""));
        }

        // " [status]" at the end of the item: status words, several joined with ", ".
        const string Word = @"(?:gone|no access|unsigned|(?:invalid|revoked|expired) signature|volume not mounted|> \d+ MB, not hashed)";
        static readonly System.Text.RegularExpressions.Regex Status =
            new System.Text.RegularExpressions.Regex(@" \[" + Word + "(?:, " + Word + @")*\]$");
    }

    /// <summary>Times are written the same on every PC, whatever its culture.</summary>
    public class CultureTests
    {
        static void Under(CultureInfo culture, Action check)
        {
            var before = Thread.CurrentThread.CurrentCulture;
            Thread.CurrentThread.CurrentCulture = culture;
            try { check(); }
            finally { Thread.CurrentThread.CurrentCulture = before; }
        }

        static CultureInfo DotTimeSeparator()
        {
            var culture = (CultureInfo)CultureInfo.InvariantCulture.Clone();
            culture.DateTimeFormat.TimeSeparator = ".";
            culture.DateTimeFormat.DateSeparator = "/";
            return culture;
        }

        [Fact]
        public void TimesUseTheGregorianCalendarAndColons()
        {
            var t = new DateTime(2026, 11, 19, 21, 9, 24, DateTimeKind.Utc);
            foreach (var culture in new[] { new CultureInfo("ar-SA"), new CultureInfo("th-TH"), DotTimeSeparator() })
                Under(culture, () =>
                {
                    Assert.Equal("2026-11-19 21:09:24", Log.T(t));
                    Assert.Equal("2026-11-19 21:09:24 UTC", Util.Utc(t));
                });
        }
    }

    public class UtilTests
    {
        [Fact]
        public void FileTimesUseTheOffsetOfTheScanLikeFrst()
        {
            // A file written in summer (UTC+2 in Berlin), scanned in winter (UTC+1): FRST shows 11:00, not 12:00.
            var summer = new DateTime(2026, 7, 1, 10, 0, 0, DateTimeKind.Utc);
            Assert.Equal("2026-07-01 11:00:00", Log.T(Util.FrstLocal(summer, TimeSpan.FromHours(1))));
            Assert.Equal("2026-07-01 04:30:00", Log.T(Util.FrstLocal(summer, TimeSpan.FromHours(-5.5))));
            Assert.Equal(DateTimeKind.Unspecified, Util.FrstLocal(summer, TimeSpan.Zero).Kind);
        }

        [Theory]
        [InlineData(@"\\?\C:\Users\Bob\x.exe", @"C:\Users\Bob\x.exe")]
        [InlineData(@"\??\C:\Windows\System32\drivers\x.sys", @"C:\Windows\System32\drivers\x.sys")]
        [InlineData(@"\\?\UNC\server\share\x.exe", @"\\server\share\x.exe")]
        [InlineData(@"\\server\share\x.exe", @"\\server\share\x.exe")]
        [InlineData(@" C:\x.exe ", @"C:\x.exe")]
        [InlineData(null, "")]
        public void DevicePrefixesAreRemoved(string path, string expected)
        {
            Assert.Equal(expected, Util.StripDevicePrefix(path));
        }

        [Fact]
        public void ClipKeepsOneLineWithoutControlCharacters()
        {
            Assert.Equal("from https://www.virustotal.com/", Util.Clip("from https://www.virustotal.com/\0"));
            Assert.Equal("a b", Util.Clip("a\r\nb"));
            Assert.Equal("a\tb", Util.Clip("a\tb\u0007"));
            Assert.Equal("Quarantäne", Util.Clip("Quarantäne"));
            Assert.Equal("", Util.Clip(null));
        }
    }
}
