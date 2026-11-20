using System;
using System.Linq;
using System.Text.RegularExpressions;

namespace Spor
{
    /// <summary>
    /// DNS host names of beacons: a per-victim ID in the name (every victim resolves its own subdomain), and TLDs campaigns favour.
    /// Pure functions over a host name; the lists are kept here in one place.
    /// </summary>
    static class HostNames
    {
        /// <summary>CDN and cloud suffixes whose host names carry IDs for normal reasons.</summary>
        public static readonly string[] CdnSuffixes =
        {
            "cloudfront.net", "akamaiedge.net", "akamaihd.net", "azureedge.net", "azurefd.net",
            "windows.net", "amazonaws.com", "googleusercontent.com", "gvt1.com", "fastly.net",
            "msedge.net", "trafficmanager.net", "cloudapp.net",
            "googlevideo.com", "1e100.net", "akamaized.net", "edgekey.net", "edgesuite.net", "llnwd.net", "azurewebsites.net",
        };

        /// <summary>Cheap TLDs malware campaigns favour. Listed in the log, not a finding on their own.</summary>
        public static readonly string[] AbusedTlds =
        {
            "click", "space", "top", "xyz", "shop", "icu", "cfd", "sbs", "monster", "rest", "bond", "lol", "cyou", "buzz",
        };

        static readonly Regex Mac = new Regex(@"^[0-9a-f]{12}$", Util.RX);
        static readonly Regex Hex32 = new Regex(@"^[0-9a-f]{32}$", Util.RX);
        static readonly Regex Guid = new Regex(@"^[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}$", Util.RX);
        // letters and digits only: CDN node names ("rr10---sn-4g5e6nzl") have dashes
        static readonly Regex LongId = new Regex(@"^[a-z0-9]{16,63}$", Util.RX);

        static string[] Labels(string host) => (host ?? "").Trim().TrimEnd('.').ToLowerInvariant().Split('.');

        /// <summary>
        /// The first label is an ID: 12 hex digits (a MAC address), 32 hex digits, a GUID with or without dashes, or 16+ letters and digits
        /// (base32 / base64 without symbols) with at least a quarter digits and a quarter letters (the DNS cache is lower case, so mixed
        /// case cannot be seen).
        /// </summary>
        public static bool IsId(string label)
        {
            if (string.IsNullOrEmpty(label)) return false;
            if (Mac.IsMatch(label) && label.Any(char.IsDigit) || Hex32.IsMatch(label) || Guid.IsMatch(label)) return true;
            if (!LongId.IsMatch(label)) return false;
            int digits = label.Count(char.IsDigit), letters = label.Count(char.IsLetter);
            return digits * 4 >= label.Length && letters * 4 >= label.Length;
        }

        /// <summary>
        /// "victim ID in name": an ID as the first label of a direct child of a registrable domain (id.example.com: two labels follow),
        /// not under a CDN or cloud suffix.
        /// </summary>
        public static bool VictimId(string host)
        {
            var l = Labels(host);
            if (l.Length != 3 || l.Any(x => x.Length == 0)) return false;
            var suffix = l[1] + "." + l[2];
            if (CdnSuffixes.Any(s => suffix.Equals(s, StringComparison.OrdinalIgnoreCase) || suffix.EndsWith("." + s, StringComparison.OrdinalIgnoreCase))) return false;
            return IsId(l[0]);
        }

        public static bool AbusedTld(string host)
        {
            var l = Labels(host);
            return l.Length >= 2 && l[l.Length - 2].Length > 0 && AbusedTlds.Contains(l[l.Length - 1]);
        }
    }
}
