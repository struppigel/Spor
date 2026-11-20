using Spor.Modules;
using Xunit;

namespace Spor.Tests
{
    /// <summary>Invisible characters in names: shown as &lt;U+XXXX&gt;, flagged !invisible-char; bidi stays &lt;RLO&gt;.</summary>
    public class InvisibleTests
    {
        [Theory]
        [InlineData("E:\\\u00A0\\x.exe", "E:\\<U+00A0>\\x.exe")]
        [InlineData("E:\\\u3164\\x.exe", "E:\\<U+3164>\\x.exe")]
        [InlineData("E:\\\u2800", "E:\\<U+2800>")]
        [InlineData("E:\\a\u200Bb", "E:\\a<U+200B>b")]
        [InlineData("E:\\doc\u202Efdp.exe", "E:\\doc<RLO>fdp.exe")]
        [InlineData("C:\\normal name\\x.exe", "C:\\normal name\\x.exe")]
        public void Fix(string raw, string shown) => Assert.Equal(shown, Rules.Fix(raw));

        /// <summary>Everywhere: only characters never used in names. A no-break space, ZWNJ or ideographic space is normal text.</summary>
        [Theory]
        [InlineData("C:\\x\\\u3164\\a.exe", true)]
        [InlineData("C:\\x\\\u2800.exe", true)]
        [InlineData("C:\\x\\a\u200Bb.exe", true)]
        [InlineData("C:\\x\\\uFEFFa.exe", true)]
        [InlineData("C:\\Downloads\\Page\u00A0Title.exe", false)]
        [InlineData("C:\\Users\\x\\\u0645\u06CC\u200C\u062E\u0648\u0627\u0647\u0645.exe", false)]   // Persian with ZWNJ
        [InlineData("C:\\x\\\u65E5\u672C\u3000\u8A9E.exe", false)]                                    // ideographic space
        [InlineData("E:\\files\\x.exe", false)]
        public void Flag(string path, bool flagged) => Assert.Equal(flagged, Rules.Flags(path).Contains(Rules.InvisibleFlag));

        [Fact]
        public void BidiStaysRlo() => Assert.Contains("!RLO", Rules.Flags("E:\\doc\u202Efdp.exe"));

        [Fact]
        public void OddCharsOnlyForHidingCharacters()
        {
            Assert.True(Rules.OddChars("a\u3164b"));
            Assert.True(Rules.OddChars("a\u202Eb"));
            Assert.False(Rules.OddChars("a\u00A0b"));
        }

        /// <summary>On a drive (USB DRIVES): every invisible character, and blanks or dots at the edge of a name.</summary>
        [Theory]
        [InlineData("E:\\\u00A0\\x.exe", true)]
        [InlineData("E:\\\u3000", true)]
        [InlineData("E:\\data \\x.exe", true)]
        [InlineData("E:\\x.\\y", true)]
        [InlineData("E:\\Photos\\cat.jpg", false)]
        public void UsbFlag(string path, bool flagged) => Assert.Equal(flagged, Usb.UsbFlags(path).Contains(Rules.InvisibleFlag));

        [Fact]
        public void ShownEverywhere() => Assert.Equal("C:\\a<U+00A0>b", Rules.Fix("C:\\a\u00A0b"));

        [Theory]
        [InlineData("E:\\ ", "E:\\<U+0020>")]
        [InlineData("E:\\data \\x.exe", "E:\\data<U+0020>\\x.exe")]
        [InlineData("E:\\x.\\y", "E:\\x<U+002E>\\y")]
        [InlineData("E:\\ a", "E:\\<U+0020>a")]
        [InlineData("E:\\\u00A0", "E:\\<U+00A0>")]
        [InlineData("E:\\.hidden\\a b.txt", "E:\\.hidden\\a b.txt")]
        public void ShownMarksEdgeBlanks(string raw, string shown) => Assert.Equal(shown, Usb.Shown(raw));

        [Fact]
        public void EdgeName()
        {
            Assert.True(Usb.EdgeName(" "));
            Assert.True(Usb.EdgeName("x."));
            Assert.False(Usb.EdgeName(".git"));
            Assert.False(Usb.EdgeName("a b"));
        }
    }
}
