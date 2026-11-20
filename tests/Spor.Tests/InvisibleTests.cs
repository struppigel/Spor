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

        [Fact]
        public void Flag()
        {
            Assert.Contains(Rules.InvisibleFlag, Rules.Flags("E:\\\u00A0\\x.exe"));
            Assert.DoesNotContain(Rules.InvisibleFlag, Rules.Flags("E:\\files\\x.exe"));
            Assert.Contains("!RLO", Rules.Flags("E:\\doc\u202Efdp.exe"));
        }

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
