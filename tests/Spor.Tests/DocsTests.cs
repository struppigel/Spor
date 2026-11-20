using System;
using System.IO;
using System.Linq;
using Xunit;

namespace Spor.Tests
{
    /// <summary>Every flag of the LEGEND is documented: its meaning in LOG-FORMAT.md, its module in MODULES.md.</summary>
    public class DocsTests
    {
        static string Doc(string name)
        {
            var dir = new DirectoryInfo(AppDomain.CurrentDomain.BaseDirectory);
            while (dir != null && !File.Exists(Path.Combine(dir.FullName, "Spor.csproj"))) dir = dir.Parent;
            Assert.NotNull(dir);
            return File.ReadAllText(Path.Combine(dir.FullName, "docs", name));
        }

        static string[] Flags => Rules.FlagLegend.Select(f => f.Substring(0, f.IndexOf(" = ", StringComparison.Ordinal))).ToArray();

        [Fact]
        public void LegendEntriesAreFlagEqualsText()
        {
            // the LEGEND writer splits at " = " and pads the flag
            Assert.All(Rules.FlagLegend, f => Assert.Matches(@"^![A-Za-z][A-Za-z-]+ = \S", f));
        }

        [Fact]
        public void EveryFlagIsInLogFormat()
        {
            var doc = Doc("LOG-FORMAT.md");
            Assert.All(Flags, f => Assert.Contains("`" + f + "`", doc));
        }

        [Fact]
        public void EveryFlagIsInModules()
        {
            var doc = Doc("MODULES.md");
            Assert.All(Flags, f => Assert.Contains("`" + f + "`", doc));
        }

        [Fact]
        public void HintsAreLegendFlags() => Assert.All(Rules.Hints, h => Assert.Contains(h, Flags));
    }
}
