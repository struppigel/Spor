using Xunit;

namespace Spor.Tests
{
    /// <summary>Random-looking and lure names, and !renamed-program.</summary>
    public class NamesTests
    {
        [Theory]
        [InlineData("ehyISWlPN")]
        [InlineData("1EXts5jt7")]
        [InlineData("xQ7pLmZr.exe")]
        public void RandomNames(string name) => Assert.True(Names.IsRandom(name), name + ": " + Names.RandomScore(name));

        [Theory]
        [InlineData("ChromeSetup")]
        [InlineData("vlc-3.0.20-win64")]
        [InlineData("setup_x64")]
        [InlineData("OBS-Studio-30.1-Full-Installer-x64")]
        [InlineData("npp.8.6.Installer.x64")]
        [InlineData("EventEmitter")]
        [InlineData("WinRAR")]
        [InlineData("x64dbg")]
        [InlineData("CCleaner64")]
        [InlineData("qBittorrent")]
        [InlineData("WinSCP")]
        [InlineData("KeePass")]
        [InlineData("Telegram")]
        [InlineData("AnyDesk")]
        public void NormalNames(string name) => Assert.False(Names.IsRandom(name), name + ": " + Names.RandomScore(name));

        [Theory]
        [InlineData("report (1).exe", "report")]
        [InlineData("tool-2.exe", "tool")]
        [InlineData("tool_1.exe", "tool")]
        [InlineData(@"C:\x\Setup - Copy.exe", "Setup")]
        [InlineData("vlc-3.0.20-win64.exe", "vlc-3.0.20-win64")]
        public void BaseDropsFolderExtensionAndCopySuffix(string name, string expected) => Assert.Equal(expected, Names.Base(name));

        [Fact]
        public void RandomNameNotTheOriginal()
        {
            // a signed developer tool renamed to random letters; no version resource, the PDB name is the original
            Assert.True(Names.RenamedProgram("ehyISWlPN.exe", null, null, @"D:\src\EventEmitter.pdb"));
        }

        [Fact]
        public void LureNameNotTheOriginal()
        {
            Assert.True(Names.RenamedProgram("Invoice_2026.exe", "putty.exe", "PuTTY", null));
            Assert.True(Names.RenamedProgram("Payment receipt.exe", "AnyDesk.exe", null, null));
        }

        [Theory]
        [InlineData("ChromeSetup.exe", "mini_installer.exe", null, null)]            // both are setup names
        [InlineData("npp.8.6.Installer.x64.exe", "npp.exe", null, null)]              // the original name is inside
        [InlineData("vlc-3.0.20-win64.exe", "vlc.exe", null, null)]
        [InlineData("OBS-Studio-30.1-Full-Installer-x64.exe", "OBS Studio Installer", null, null)]
        [InlineData("putty (1).exe", "PuTTY", null, null)]                            // a second download
        [InlineData("Discord.exe", "Update.exe", null, null)]                         // different, but neither random nor a lure
        [InlineData("tool.exe", null, null, null)]                                    // nothing to compare with
        public void NotRenamed(string file, string original, string internalName, string pdb) =>
            Assert.False(Names.RenamedProgram(file, original, internalName, pdb));

        [Fact]
        public void HintsAreNotStrong()
        {
            Assert.Empty(Rules.Strong(new System.Collections.Generic.List<string> { "!renamed-program", "!lolbin" }));
            Assert.Equal(new[] { "!sideload" }, Rules.Strong(new System.Collections.Generic.List<string> { "!renamed-program", "!sideload" }));
        }
    }
}
