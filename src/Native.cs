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
    }
}
