using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32;

namespace Spor.Modules
{
    /// <summary>
    /// Local accounts: enabled, administrator, password set, last logon, hidden from the logon screen; Administrators members;
    /// account events (created, enabled, password reset, added to a group, deleted) from the Security log.
    /// Remote access attackers and some malware create (hidden) admin accounts.
    /// </summary>
    class Accounts : IModule
    {
        public string Id => "accounts";
        public string Name => "ACCOUNTS";
        public string Description => "local accounts, last sign-in, administrators, hidden accounts, account changes";

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct USER_INFO_3
        {
            public string name, password; public uint password_age, priv; public string home_dir, comment; public uint flags;
            public string script_path; public uint auth_flags; public string full_name, usr_comment, parms, workstations;
            public uint last_logon, last_logoff, acct_expires, max_storage, units_per_week; public IntPtr logon_hours;
            public uint bad_pw_count, num_logons; public string logon_server; public uint country_code, code_page;
            public uint user_id, primary_group_id; public string profile, home_dir_drive; public uint password_expired;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct LOCALGROUP_MEMBERS_INFO_2 { public IntPtr sid; public int sidusage; public string domainandname; }

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)] static extern int NetUserEnum(string server, int level, int filter, out IntPtr buf, int max, out int read, out int total, ref int resume);
        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)] static extern int NetLocalGroupGetMembers(string server, string group, int level, out IntPtr buf, int max, out int read, out int total, IntPtr resume);
        [DllImport("netapi32.dll")] static extern int NetApiBufferFree(IntPtr buf);

        Ctx c;

        public void Execute(Ctx ctx)
        {
            c = ctx;
            var hidden = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                using (var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList"))
                    if (k != null) foreach (var n in k.GetValueNames()) if (Convert.ToInt32(k.GetValue(n) ?? 1) == 0) hidden.Add(n);
            }
            catch { }

            c.Out.Sub("Local accounts", "password set = when the password was last set (for a new account: when it was created)\nlast sign-in = when Windows last loaded the profile; - with \"no profile\" = never signed in");
            var at = new Table("password set", "=state", "=role", "<flags", "*account", "last sign-in", "full name", "sid");
            var msid = Native.MachineSid();
            var builtin = new HashSet<uint> { 500, 501, 503, 504 };   // Administrator, Guest, DefaultAccount, WDAGUtilityAccount (by RID: names are localized)
            int resume = 0;
            if (NetUserEnum(null, 3, 2, out var buf, -1, out int read, out _, ref resume) == 0)
            {
                try
                {
                    int sz = Marshal.SizeOf(typeof(USER_INFO_3));
                    for (int i = 0; i < read; i++)
                    {
                        var u = (USER_INFO_3)Marshal.PtrToStructure(buf + i * sz, typeof(USER_INFO_3));
                        bool enabled = (u.flags & 2) == 0, admin = u.priv == 2;
                        var pwSet = DateTime.UtcNow.AddSeconds(-u.password_age);
                        // last sign-in: when Windows last loaded the user's profile (every sign-in, also with PIN/Windows Hello/Microsoft
                        // account); usri_last_logon only counts classic password logons. No profile = never signed in interactively.
                        var (hasProfile, loaded) = ProfileLoad(u.name);
                        DateTime? last = u.last_logon > 0 ? DateTimeOffset.FromUnixTimeSeconds(u.last_logon).UtcDateTime : (DateTime?)null;
                        if (loaded.HasValue && (!last.HasValue || loaded > last)) last = loaded;
                        if (Rules.Whitelist && !enabled && builtin.Contains(u.user_id)) continue;
                        var fl = new List<string>();
                        if (hidden.Contains(u.name) && enabled) fl.Add("!hidden-account");
                        bool recent = pwSet >= c.Since;
                        at.Add(Log.T(pwSet), enabled ? "enabled" : "disabled", admin ? "admin" : "user", Rules.FlagCol(fl), u.name,
                               last.HasValue ? Log.T(last) : hasProfile ? "-" : "no profile", u.full_name, Sid(msid, u.name, u.user_id));
                        if (recent && enabled) c.Event(pwSet, "USR", null, text: $"password of {(admin ? "admin" : "user")} account {u.name} set (or account created)");
                        if (fl.Count > 0 || (recent && enabled && admin && !builtin.Contains(u.user_id) && !hasProfile && u.password_age > 0))
                            c.Find(pwSet, $"account {u.name} ({(admin ? "admin" : "user")}){Rules.FlagText(fl)}, password set {pwSet:yyyy-MM-dd HH:mm}{(hasProfile ? "" : ", never signed in")}");
                    }
                }
                finally { NetApiBufferFree(buf); }
            }
            else c.Err.Add("cannot list local accounts");
            at.WriteTo(c.Out);

            c.Out.Sub("Members of Administrators");
            try
            {
                var grp = new SecurityIdentifier("S-1-5-32-544").Translate(typeof(NTAccount)).Value.Split('\\').Last();
                if (NetLocalGroupGetMembers(null, grp, 2, out var gb, -1, out int gr, out _, IntPtr.Zero) == 0)
                {
                    try
                    {
                        int sz = Marshal.SizeOf(typeof(LOCALGROUP_MEMBERS_INFO_2));
                        var names = new List<string>();
                        for (int i = 0; i < gr; i++) names.Add(((LOCALGROUP_MEMBERS_INFO_2)Marshal.PtrToStructure(gb + i * sz, typeof(LOCALGROUP_MEMBERS_INFO_2))).domainandname);
                        var mt = new Table("*member"); foreach (var n in names) mt.Add(n); mt.WriteTo(c.Out);
                    }
                    finally { NetApiBufferFree(gb); }
                }
            }
            catch (Exception e) { c.Err.Add("Administrators: " + e.Message); }

            c.Out.Sub($"Account changes in the last {c.Opt.Days} days (Security log)");
            var ev = Ev.Query("Security", Ev.Ids(4720, 4722, 4724, 4726, 4728, 4732, 4781), c.Since, 2000, c.Err);
            var et = new Table("@time", "[event", "*change");
            foreach (var e in ev)
            {
                var t = e.TimeCreated?.ToUniversalTime();
                string text;
                switch (e.Id)
                {
                    case 4720: text = $"account {Ev.P(e, 0)} created by {Ev.P(e, 4)}"; break;
                    case 4722: text = $"account {Ev.P(e, 0)} enabled by {Ev.P(e, 4)}"; break;
                    case 4724: text = $"password of {Ev.P(e, 0)} reset by {Ev.P(e, 4)}"; break;
                    case 4726: text = $"account {Ev.P(e, 0)} deleted by {Ev.P(e, 4)}"; break;
                    case 4728: case 4732: text = $"{Member(Ev.P(e, 1), Ev.P(e, 0))} added to group {Ev.P(e, 2)} by {Ev.P(e, 6)}"; break;
                    case 4781: text = $"account {Ev.P(e, 0)} renamed to {Ev.P(e, 1)}"; break;
                    default: text = $"account event {e.Id}"; break;
                }
                et.Add(Log.T(t), e.Id.ToString(), text);
                c.Event(t, "USR", null, text: text);
                if (e.Id == 4720 || e.Id == 4732 || e.Id == 4728) c.Find(t, text);
                e.Dispose();
            }
            et.WriteTo(c.Out);
        }

        /// <summary>(profile exists, last time it was loaded) from ProfileList\SID\LocalProfileLoadTimeHigh/Low.</summary>
        static (bool, DateTime?) ProfileLoad(string user)
        {
            try
            {
                var sid = ((SecurityIdentifier)new NTAccount(user).Translate(typeof(SecurityIdentifier))).Value;
                using (var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\" + sid))
                {
                    if (k == null) return (false, null);
                    long hi = Convert.ToUInt32(k.GetValue("LocalProfileLoadTimeHigh") ?? 0), lo = Convert.ToUInt32(k.GetValue("LocalProfileLoadTimeLow") ?? 0);
                    return (true, Util.FtTime((hi << 32) | lo));
                }
            }
            catch { return (false, null); }
        }

        /// <summary>The account's full SID: machine SID + RID (usri3_user_id), else looked up by name; null if unknown.</summary>
        static string Sid(string machineSid, string name, uint rid)
        {
            if (machineSid != null && rid > 0) return machineSid + "-" + rid;
            try { return ((SecurityIdentifier)new NTAccount(Environment.MachineName, name).Translate(typeof(SecurityIdentifier))).Value; }
            catch { return null; }
        }

        static string Member(string sid, string name)
        {
            if (!string.IsNullOrEmpty(name) && name != "-") return name;
            try { return new SecurityIdentifier(sid).Translate(typeof(NTAccount)).Value; } catch { return sid; }
        }
    }
}
