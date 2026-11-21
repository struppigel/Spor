using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace Spor
{
    /// <summary>Windows APIs that .NET does not wrap.</summary>
    static class Native
    {
        [DllImport("shlwapi.dll", CharSet = CharSet.Unicode)]
        static extern int SHLoadIndirectString(string source, StringBuilder outBuf, int cch, IntPtr reserved);

        /// <summary>
        /// A resource reference as Windows writes it into task XML and the registry, "$(@%SystemRoot%\system32\usosvc.dll,-103)" or
        /// "@C:\x.dll,-5", as its text; anything else, or a reference that cannot be read, unchanged.
        /// </summary>
        public static string IndirectString(string s)
        {
            if (string.IsNullOrEmpty(s)) return s;
            var src = s.StartsWith("$(@") && s.EndsWith(")") ? s.Substring(2, s.Length - 3) : s.StartsWith("@") ? s : null;
            if (src == null) return s;
            try
            {
                var sb = new StringBuilder(1024);
                return SHLoadIndirectString(Environment.ExpandEnvironmentVariables(src), sb, sb.Capacity, IntPtr.Zero) == 0 && sb.Length > 0 ? sb.ToString() : s;
            }
            catch { return s; }
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr sec, uint disp, uint flags, IntPtr tmpl);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool DeviceIoControl(SafeFileHandle h, uint code, IntPtr inBuf, int inSize, byte[] outBuf, int outSize, out int ret, IntPtr ov);

        /// <summary>
        /// Target of an app execution alias (AppData\Local\Microsoft\WindowsApps\wt.exe, python.exe, winget.exe, ...): a 0-byte
        /// reparse point (tag APPEXECLINK) naming the package, the app id and the real exe. null if p is not such an alias.
        /// </summary>
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetFileInformationByHandleEx(SafeFileHandle h, int infoClass, byte[] info, int size);

        /// <summary>
        /// NTFS change time (when the file's metadata last changed). Setting timestamps with SetFileTime-style tools updates it to
        /// the real time, so a file whose creation time is older than its change time by days had its times set (or was renamed/moved).
        /// </summary>
        public static DateTime? ChangeTime(string p)
        {
            try
            {
                using (var h = CreateFileW(@"\\?\" + p, 0x80 /* read attributes */, 7, IntPtr.Zero, 3, 0x02000000 /* backup */, IntPtr.Zero))
                {
                    if (h.IsInvalid) return null;
                    var b = new byte[40];   // FILE_BASIC_INFO: creation, access, write, change (FILETIME each), attributes
                    if (!GetFileInformationByHandleEx(h, 0 /* FileBasicInfo */, b, b.Length)) return null;
                    long ft = BitConverter.ToInt64(b, 24);
                    return ft > 0 ? DateTime.FromFileTimeUtc(ft) : (DateTime?)null;
                }
            }
            catch { return null; }
        }

        public static string AppAlias(string p)
        {
            try
            {
                using (var h = CreateFileW(@"\\?\" + p, 0x80 /* read attributes */, 7, IntPtr.Zero, 3, 0x00200000 | 0x02000000 /* open reparse point, backup */, IntPtr.Zero))
                {
                    if (h.IsInvalid) return null;
                    var buf = new byte[16384];
                    if (!DeviceIoControl(h, 0x900A8 /* FSCTL_GET_REPARSE_POINT */, IntPtr.Zero, 0, buf, buf.Length, out int n, IntPtr.Zero) || n < 12) return null;
                    if (BitConverter.ToUInt32(buf, 0) != 0x8000001B) return null;   // IO_REPARSE_TAG_APPEXECLINK
                    // header 8 bytes, version 4 bytes, then UTF-16 strings: package family, app user model id, target exe, ...
                    var parts = Encoding.Unicode.GetString(buf, 12, n - 12).Split('\0');
                    return parts.Length >= 3 && parts[2].Length > 3 ? parts[2] : null;
                }
            }
            catch { return null; }
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        static extern int RegLoadAppKey(string file, out IntPtr key, int sam, int options, int reserved);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        static extern int RegQueryInfoKey(SafeRegistryHandle key, IntPtr cls, IntPtr clsLen, IntPtr reserved, IntPtr subKeys, IntPtr maxSubKeyLen,
            IntPtr maxClassLen, IntPtr values, IntPtr maxValueNameLen, IntPtr maxValueLen, IntPtr securityDescriptor, out long lastWrite);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        static extern uint QueryDosDevice(string name, StringBuilder target, int max);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool GetVolumeInformation(string root, StringBuilder name, int nameSize, out uint serial, out uint maxComponent,
            out uint flags, StringBuilder fs, int fsSize);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern uint GetLongPathName(string shortPath, StringBuilder longPath, int size);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern uint GetShortPathName(string longPath, StringBuilder shortPath, int size);

        [DllImport("ntdll.dll")]
        static extern uint RtlGetCompressionWorkSpaceSize(ushort format, out uint workSpace, out uint fragmentWorkSpace);

        [DllImport("ntdll.dll")]
        static extern uint RtlDecompressBufferEx(ushort format, byte[] output, uint outputSize, byte[] input, uint inputSize, out uint final, byte[] workSpace);

        /// <summary>Opens a hive file privately (not visible under HKU), read-only. Close the key to unload it.</summary>
        public static RegistryKey LoadHive(string file)
        {
            int rc = RegLoadAppKey(file, out IntPtr h, 0x20019 /* KEY_READ */, 0, 0);
            if (rc != 0) throw new Win32Exception(rc);
            return RegistryKey.FromHandle(new SafeRegistryHandle(h, true));
        }

        public static DateTime? LastWrite(RegistryKey k)
        {
            if (k == null) return null;
            return RegQueryInfoKey(k.Handle, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero,
                IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out long ft) == 0 ? Util.FtTime(ft) : null;
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        static extern int RegQueryValueExW(SafeRegistryHandle key, string name, IntPtr reserved, out uint type, byte[] data, ref int size);

        /// <summary>
        /// The bytes of a registry value whatever its type (device properties use types like 0xFFFF0010 that .NET does not read);
        /// null if missing or unreadable. name "" = the default value.
        /// </summary>
        public static byte[] RawValue(RegistryKey k, string name)
        {
            if (k == null) return null;
            try
            {
                int size = 0;
                if (RegQueryValueExW(k.Handle, name, IntPtr.Zero, out _, null, ref size) != 0 || size <= 0 || size > 1 << 20) return null;
                var b = new byte[size];
                return RegQueryValueExW(k.Handle, name, IntPtr.Zero, out _, b, ref size) == 0 ? b : null;
            }
            catch { return null; }
        }

        /// <summary>"C:" -> "\Device\HarddiskVolume3"</summary>
        public static string DosDevice(string drive)
        {
            var sb = new StringBuilder(1024);
            return QueryDosDevice(drive, sb, sb.Capacity) > 0 ? sb.ToString() : null;
        }

        /// <summary>Volume serial number as 8 upper-case hex digits, as used in prefetch paths (\VOLUME{...-XXXXXXXX}).</summary>
        public static string VolumeSerial(string root)
        {
            return GetVolumeInformation(root, null, 0, out uint serial, out _, out _, null, 0) ? serial.ToString("X8") : null;
        }

        /// <summary>The volume label (null if none or unreadable).</summary>
        public static string VolumeLabel(string root)
        {
            var sb = new StringBuilder(261);
            return GetVolumeInformation(root, sb, sb.Capacity, out _, out _, out _, null, 0) && sb.Length > 0 ? sb.ToString() : null;
        }

        /// <summary>
        /// The storage device of a drive ("E:"): bus 7 = USB, 0x11 = NVMe, 0x0B = SATA, ... (STORAGE_BUS_TYPE; -1 if unknown), vendor and
        /// product. USB hard disks report as fixed drives, the bus tells them apart.
        /// </summary>
        public static (int Bus, string Vendor, string Product) Storage(string drive)
        {
            try
            {
                using (var h = CreateFileW(@"\\.\" + drive.TrimEnd('\\'), 0, 3, IntPtr.Zero, 3, 0, IntPtr.Zero))
                {
                    if (h.IsInvalid) return (-1, null, null);
                    // STORAGE_PROPERTY_QUERY: PropertyId 0 (StorageDeviceProperty), QueryType 0 (PropertyStandardQuery), 1 byte extra
                    var q = Marshal.AllocHGlobal(12);
                    try
                    {
                        Marshal.WriteInt64(q, 0); Marshal.WriteInt32(q, 8, 0);
                        var b = new byte[1024];
                        if (!DeviceIoControl(h, 0x2D1400 /* IOCTL_STORAGE_QUERY_PROPERTY */, q, 12, b, b.Length, out int n, IntPtr.Zero) || n < 32) return (-1, null, null);
                        string S(int at)
                        {
                            int off = BitConverter.ToInt32(b, at);
                            if (off <= 0 || off >= n) return null;
                            int e = off; while (e < n && b[e] != 0) e++;
                            var s = Encoding.ASCII.GetString(b, off, e - off).Trim();
                            return s.Length > 0 ? s : null;
                        }
                        // STORAGE_DEVICE_DESCRIPTOR: ..., VendorIdOffset 12, ProductIdOffset 16, ..., BusType 28
                        return (BitConverter.ToInt32(b, 28), S(12), S(16));
                    }
                    finally { Marshal.FreeHGlobal(q); }
                }
            }
            catch { return (-1, null, null); }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct WIN32_FIND_STREAM_DATA { public long StreamSize; [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 296)] public string cStreamName; }
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern IntPtr FindFirstStreamW(string name, int level, out WIN32_FIND_STREAM_DATA data, int flags);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool FindNextStreamW(IntPtr h, out WIN32_FIND_STREAM_DATA data);
        [DllImport("kernel32.dll")] static extern bool FindClose(IntPtr h);

        /// <summary>The alternate data streams of a file or folder (name without ":$DATA", size); empty if none or unreadable.</summary>
        public static System.Collections.Generic.List<(string Name, long Size)> Streams(string path)
        {
            var res = new System.Collections.Generic.List<(string, long)>();
            var h = FindFirstStreamW(path.Length >= 250 && !path.StartsWith(@"\\?\") ? @"\\?\" + path : path, 0, out var d, 0);
            if (h == new IntPtr(-1)) return res;
            try
            {
                do
                {
                    var n = d.cStreamName ?? "";
                    if (n.EndsWith(":$DATA")) n = n.Substring(0, n.Length - 6);
                    n = n.TrimStart(':');
                    if (n.Length > 0) res.Add((n, d.StreamSize));   // "::$DATA" is the file's own content
                } while (res.Count < 100 && FindNextStreamW(h, out d));
            }
            finally { FindClose(h); }
            return res;
        }

        public static string LongPath(string p)
        {
            var sb = new StringBuilder(32768);
            uint n = GetLongPathName(p, sb, sb.Capacity);
            return n > 0 && n < sb.Capacity ? sb.ToString() : null;
        }

        public static string ShortPath(string p)
        {
            var sb = new StringBuilder(32768);
            uint n = GetShortPathName(p, sb, sb.Capacity);
            return n > 0 && n < sb.Capacity ? sb.ToString() : null;
        }

        /// <summary>XPRESS Huffman (format 4), used by Windows 10/11 prefetch files ("MAM" header).</summary>
        public static byte[] DecompressXpressHuff(byte[] input, int offset, int outputSize)
        {
            const ushort XpressHuff = 4;
            uint rc = RtlGetCompressionWorkSpaceSize(XpressHuff, out uint ws, out _);
            if (rc != 0) throw new Exception($"RtlGetCompressionWorkSpaceSize failed: 0x{rc:X}");
            var data = new byte[input.Length - offset];
            Buffer.BlockCopy(input, offset, data, 0, data.Length);
            var output = new byte[outputSize];
            rc = RtlDecompressBufferEx(XpressHuff, output, (uint)outputSize, data, (uint)data.Length, out _, new byte[ws]);
            if (rc != 0) throw new Exception($"decompression failed: 0x{rc:X}");
            return output;
        }
            [StructLayout(LayoutKind.Sequential)]
        struct LSA_OBJECT_ATTRIBUTES { public int Length; public IntPtr RootDirectory, ObjectName; public uint Attributes; public IntPtr SecurityDescriptor, SecurityQualityOfService; }
        [StructLayout(LayoutKind.Sequential)]
        struct POLICY_ACCOUNT_DOMAIN_INFO { public ushort NameLength, NameMax; public IntPtr NameBuffer; public IntPtr DomainSid; }
        [DllImport("advapi32.dll")] static extern uint LsaOpenPolicy(IntPtr system, ref LSA_OBJECT_ATTRIBUTES oa, uint access, out IntPtr handle);
        [DllImport("advapi32.dll")] static extern uint LsaQueryInformationPolicy(IntPtr handle, int infoClass, out IntPtr buffer);
        [DllImport("advapi32.dll")] static extern uint LsaFreeMemory(IntPtr buffer);
        [DllImport("advapi32.dll")] static extern uint LsaClose(IntPtr handle);

        static string machineSid; static bool machineSidRead;

        /// <summary>
        /// The local account domain SID (S-1-5-21-a-b-c, without a RID): the same for every local account of this Windows install,
        /// new after a reinstall. LSA PolicyAccountDomainInformation; fallback: a local account's SID without its RID. null if unknown.
        /// </summary>
        public static string MachineSid()
        {
            if (machineSidRead) return machineSid;
            machineSidRead = true;
            try
            {
                var oa = new LSA_OBJECT_ATTRIBUTES { Length = Marshal.SizeOf(typeof(LSA_OBJECT_ATTRIBUTES)) };
                if (LsaOpenPolicy(IntPtr.Zero, ref oa, 1 /* POLICY_VIEW_LOCAL_INFORMATION */, out var h) == 0)
                {
                    try
                    {
                        if (LsaQueryInformationPolicy(h, 5 /* PolicyAccountDomainInformation */, out var buf) == 0)
                        {
                            try
                            {
                                var info = (POLICY_ACCOUNT_DOMAIN_INFO)Marshal.PtrToStructure(buf, typeof(POLICY_ACCOUNT_DOMAIN_INFO));
                                if (info.DomainSid != IntPtr.Zero) machineSid = new System.Security.Principal.SecurityIdentifier(info.DomainSid).Value;
                            }
                            finally { LsaFreeMemory(buf); }
                        }
                    }
                    finally { LsaClose(h); }
                }
            }
            catch { }
            if (machineSid == null)
                try
                {
                    // the built-in Administrator (RID 500) exists on every install, also renamed or disabled
                    var sid = ((System.Security.Principal.SecurityIdentifier)new System.Security.Principal.NTAccount(Environment.MachineName, "Administrator")
                               .Translate(typeof(System.Security.Principal.SecurityIdentifier))).Value;
                    if (System.Text.RegularExpressions.Regex.IsMatch(sid, @"^S-1-5-21-\d+-\d+-\d+-\d+$")) machineSid = sid.Substring(0, sid.LastIndexOf('-'));
                }
                catch { }
            if (machineSid != null && !System.Text.RegularExpressions.Regex.IsMatch(machineSid, @"^S-1-5-21-\d+-\d+-\d+$")) machineSid = null;
            return machineSid;
        }

        // ---- processes ----
        [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool QueryFullProcessImageName(IntPtr h, int flags, StringBuilder name, ref int size);
        [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
        [DllImport("psapi.dll", SetLastError = true)] static extern bool EnumProcessModulesEx(IntPtr h, [Out] IntPtr[] modules, int size, out int needed, uint filter);
        [DllImport("psapi.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern int GetModuleFileNameEx(IntPtr h, IntPtr module, StringBuilder name, int size);

        const uint QueryLimited = 0x1000, QueryInformation = 0x0400, VmRead = 0x0010, ListModulesAll = 3;

        /// <summary>The program file of a running process (needs only limited query rights), or null.</summary>
        public static string ProcessPath(int pid)
        {
            var h = OpenProcess(QueryLimited, false, pid);
            if (h == IntPtr.Zero) return null;
            try { var sb = new StringBuilder(1024); int n = sb.Capacity; return QueryFullProcessImageName(h, 0, sb, ref n) ? sb.ToString() : null; }
            finally { CloseHandle(h); }
        }

        /// <summary>
        /// The files of the modules (EXE and DLLs) a process has loaded, 32- and 64-bit; null when the process cannot be opened
        /// (protected processes, or Spor running as a 32-bit process looking at a 64-bit one). Only reads the module list.
        /// </summary>
        public static System.Collections.Generic.List<string> ProcessModules(int pid)
        {
            var h = OpenProcess(QueryInformation | VmRead, false, pid);
            if (h == IntPtr.Zero) return null;
            try
            {
                var mods = new IntPtr[1024];
                int size = mods.Length * IntPtr.Size;
                if (!EnumProcessModulesEx(h, mods, size, out int needed, ListModulesAll)) return null;
                if (needed > size)
                {
                    mods = new IntPtr[needed / IntPtr.Size + 16];
                    size = mods.Length * IntPtr.Size;
                    if (!EnumProcessModulesEx(h, mods, size, out needed, ListModulesAll)) return null;
                }
                var res = new System.Collections.Generic.List<string>();
                for (int i = 0; i < Math.Min(needed, size) / IntPtr.Size; i++)
                {
                    var sb = new StringBuilder(1024);
                    if (GetModuleFileNameEx(h, mods[i], sb, sb.Capacity) > 0) res.Add(sb.ToString());
                }
                return res;
            }
            finally { CloseHandle(h); }
        }
    }
}
