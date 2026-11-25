using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Web.Script.Serialization;

namespace Spor
{
    /// <summary>
    /// (pure) Chromium browser extensions from a profile's Preferences / Secure Preferences: the ones not installed from a store
    /// (loaded unpacked, location 4, or from the command line, location 8) and whether developer mode is on. Malware patches wallet
    /// extensions (MetaMask, Phantom, ...) and loads its copy unpacked, hiding the developer mode warning (WEEVILPROXY).
    /// </summary>
    static class BrowserExtensions
    {
        public const string UnpackedFlag = "!unpacked-extension";
        public const string DevModeFlag = "!dev-mode";

        /// <summary>The most text read from one Preferences file.</summary>
        public const int MaxText = 32 * 1024 * 1024;

        public sealed class Ext { public string Id, Name, Path, Location; }

        static object Get(object o, string key) => o is IDictionary d && d.Contains(key) ? d[key] : null;

        /// <summary>The value at a dotted path ("extensions.ui.developer_mode").</summary>
        static object At(object o, string path)
        {
            foreach (var k in path.Split('.')) { o = Get(o, k); if (o == null) return null; }
            return o;
        }

        /// <summary>(pure) Developer mode and the extensions that are not from a store, of one Preferences JSON text (null: not parsable).</summary>
        public static (bool DevMode, List<Ext> Unpacked)? Parse(string json)
        {
            if (string.IsNullOrWhiteSpace(json) || json.Length > MaxText) return null;
            object root;
            try { root = new JavaScriptSerializer { MaxJsonLength = MaxText, RecursionLimit = 200 }.DeserializeObject(json); }
            catch (Exception) { return null; }
            bool dev = At(root, "extensions.ui.developer_mode") is bool b && b;
            var list = new List<Ext>();
            if (At(root, "extensions.settings") is IDictionary settings)
                foreach (DictionaryEntry e in settings)
                {
                    var loc = Convert.ToString(Get(e.Value, "location"));
                    if (loc != "4" && loc != "8") continue;   // UNPACKED, COMMAND_LINE
                    list.Add(new Ext
                    {
                        Id = Convert.ToString(e.Key),
                        Name = Convert.ToString(At(e.Value, "manifest.name") ?? ""),
                        Path = Convert.ToString(Get(e.Value, "path") ?? ""),
                        Location = loc == "4" ? "loaded unpacked" : "loaded from the command line",
                    });
                }
            return (dev, list);
        }

        /// <summary>An unpacked extension's name from its manifest.json ("" when unknown or a __MSG_ placeholder).</summary>
        public static string ManifestName(string folder)
        {
            try
            {
                var f = System.IO.Path.Combine(folder, "manifest.json");
                if (!File.Exists(f) || new FileInfo(f).Length > 1024 * 1024) return "";
                var name = Convert.ToString(Get(new JavaScriptSerializer().DeserializeObject(Util.ReadText(f)), "name") ?? "");
                return name.StartsWith("__MSG_") ? "" : name;
            }
            catch { return ""; }
        }
    }
}
