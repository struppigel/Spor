using Xunit;

namespace Spor.Tests
{
    /// <summary>!motw-removed: a lowered zone without a URL on a new program in a drop location.</summary>
    public class MotwTests
    {
        static Zone Z(string text) => Ads.ParseZone(text);

        [Theory]
        [InlineData(@"C:\Users\anna\AppData\Local\Temp\tmp-1-x\a.exe", "[ZoneTransfer]\r\nZoneId=0\r\n")]
        [InlineData(@"C:\Users\anna\Downloads\x\run.js", "[ZoneTransfer]\r\nZoneId=1\r\n")]
        [InlineData(@"C:\Users\anna\Desktop\Invoice.lnk", "[ZoneTransfer]\r\nZoneId=2\r\n")]
        [InlineData(@"C:\Users\anna\AppData\Roaming\x\a.dll", "[ZoneTransfer]\r\nZoneId=0\r\nHostUrl=about:internet\r\n")]
        public void LoweredZoneOnANewProgramInADropLocation(string path, string zone)
        {
            Assert.True(Rules.MotwRemoved(path, Z(zone)));
        }

        [Fact]
        public void ABrowserDownloadIsNot()
        {
            Assert.False(Rules.MotwRemoved(@"C:\Users\anna\Downloads\setup.exe", Z("[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://example.com/setup.exe\r\n")));
        }

        [Fact]
        public void ADocumentIsNot()
        {
            Assert.False(Rules.MotwRemoved(@"C:\Users\anna\Downloads\notes.txt", Z("[ZoneTransfer]\r\nZoneId=0\r\n")));
        }

        [Fact]
        public void AFileInProgramFilesIsNot()
        {
            Assert.False(Rules.MotwRemoved(@"C:\Program Files\Vendor\app.exe", Z("[ZoneTransfer]\r\nZoneId=0\r\n")));
        }

        [Fact]
        public void ALowZoneWithAUrlIsNot()
        {
            // an intranet download keeps its URL
            Assert.False(Rules.MotwRemoved(@"C:\Users\anna\Downloads\tool.exe", Z("[ZoneTransfer]\r\nZoneId=1\r\nHostUrl=http://intranet/tool.exe\r\n")));
        }

        [Fact]
        public void NoStreamIsNot()
        {
            Assert.False(Rules.MotwRemoved(@"C:\Users\anna\AppData\Local\Temp\x\a.exe", null));
        }
    }
}
