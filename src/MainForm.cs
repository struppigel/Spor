using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Spor
{
    /// <summary>The window: choose what to scan, Scan, the log opens in Notepad.</summary>
    class MainForm : Form
    {
        readonly Dictionary<string, CheckBox> mods = new Dictionary<string, CheckBox>();
        readonly CheckBox whitelist, hash;
        readonly NumericUpDown days;
        readonly Button scan, open;
        readonly ProgressBar bar;
        readonly Label status;
        readonly ComboBox profile;
        const string Custom = "Custom";
        string logPath;
        bool running, applying;

        static readonly (string Id, string Text)[] ModuleTexts =
            Scanner.All.Select(m => (m.Id, Scanner.Pretty(m))).ToArray();

        public MainForm()
        {
            Text = "Spor " + Scanner.Version;
            try { Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); } catch { }   // the exe's own icon (resources\Spor.ico)
            Font = SystemFonts.MessageBoxFont;
            AutoScaleMode = AutoScaleMode.Font;
            FormBorderStyle = FormBorderStyle.FixedSingle;
            MaximizeBox = false;
            StartPosition = FormStartPosition.CenterScreen;
            AutoSize = true;
            AutoSizeMode = AutoSizeMode.GrowAndShrink;

            // one column, everything auto-sized from its content (no GroupBox: its auto-size does not grow with long check box texts)
            var root = new TableLayoutPanel { ColumnCount = 1, AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, Padding = new Padding(14), Location = new Point(0, 0) };
            root.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            Controls.Add(root);
            void Add(Control ctl) { root.RowCount++; root.RowStyles.Add(new RowStyle(SizeType.AutoSize)); root.Controls.Add(ctl, 0, root.RowCount - 1); }
            Label Head(string t) => new Label { Text = t, AutoSize = true, Font = new Font(Font, FontStyle.Bold), Margin = new Padding(0, 12, 0, 4) };

            Add(new Label
            {
                Text = "Spor collects traces of malware and remote access tools and saves them to Spor.txt.\r\nNothing on this PC is changed. Send the log to the person helping you.",
                AutoSize = true, Margin = new Padding(0, 0, 0, 4)
            });

            // profile: ticks its modules; ticking boxes by hand shows the matching profile, else "Custom"
            Add(Head("What to scan"));
            // "Profile: [list]" only: the module grid below sets the window's width
            var pr = new FlowLayoutPanel { AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, Margin = new Padding(8, 0, 0, 6), WrapContents = false };
            pr.Controls.Add(new Label { Text = "Profile:", AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(0, 0, 6, 0) });   // Left: centred on the list's row
            profile = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Anchor = AnchorStyles.Left, Margin = new Padding(0, 0, 0, 0) };
            foreach (var p in Scanner.Profiles) profile.Items.Add(p.Name);
            profile.Items.Add(Custom);
            // wide enough for the longest entry at any font size (a fixed pixel width does not scale with the font)
            profile.Width = profile.Items.Cast<string>().Max(s => TextRenderer.MeasureText(s, Font).Width) + SystemInformation.VerticalScrollBarWidth + 16;
            pr.Controls.Add(profile);
            Add(pr);

            // modules in a grid, filled column by column (3 columns)
            const int cols = 3;
            int rows = (ModuleTexts.Length + cols - 1) / cols;
            var grid = new TableLayoutPanel { ColumnCount = cols, RowCount = rows, AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, Margin = new Padding(8, 0, 0, 0) };
            for (int i = 0; i < cols; i++) grid.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            for (int i = 0; i < rows; i++) grid.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            for (int i = 0; i < ModuleTexts.Length; i++)
            {
                var (id, text) = ModuleTexts[i];
                var cb = new CheckBox { Text = text, AutoSize = true, Margin = new Padding(0, 1, 24, 1) };
                cb.CheckedChanged += (s, e) => { if (!applying) ShowProfile(); };
                mods[id] = cb; grid.Controls.Add(cb, i / rows, i % rows);
            }
            Add(grid);
            profile.SelectedIndexChanged += (s, e) => ApplyProfile();
            profile.SelectedIndex = 0;   // Default

            // options in one row
            Add(Head("Options"));
            var dl = new FlowLayoutPanel { AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, Margin = new Padding(8, 0, 0, 0), WrapContents = false };
            whitelist = new CheckBox { Text = "Whitelist", Checked = true, AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(0, 4, 24, 3) };
            hash = new CheckBox { Text = "File hashes", Checked = true, AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(0, 4, 24, 3) };
            days = new NumericUpDown { Minimum = 1, Maximum = 3650, Value = 30, Width = 70 };
            dl.Controls.Add(whitelist);
            dl.Controls.Add(hash);
            dl.Controls.Add(new Label { Text = "Time window:", AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(0, 6, 3, 3) });
            dl.Controls.Add(days);
            dl.Controls.Add(new Label { Text = "days", AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(3, 6, 3, 3) });
            Add(dl);

            var fb = new FlowLayoutPanel { AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, Margin = new Padding(0, 14, 0, 0), WrapContents = false };
            scan = new Button { Text = "Scan", AutoSize = true, MinimumSize = new Size(110, 32) };
            open = new Button { Text = "Open log", AutoSize = true, MinimumSize = new Size(110, 32), Enabled = false };
            scan.Click += (s, e) => StartScan();
            open.Click += (s, e) => { if (logPath != null) Program.OpenLog(logPath); };
            fb.Controls.Add(scan); fb.Controls.Add(open);
            Add(fb);

            bar = new ProgressBar { Height = 18, Dock = DockStyle.Fill, Margin = new Padding(0, 10, 0, 4) };
            // fixed size: fills the column width set by the other controls and has room for two lines (progress and the log path),
            // so a long status text wraps instead of resizing the window
            status = new Label { AutoSize = false, Dock = DockStyle.Fill, Height = Font.Height * 2 + 6, Text = "Ready.", Margin = new Padding(0, 2, 0, 0) };
            Add(bar); Add(status);
            AcceptButton = scan;

            // after the first layout the window keeps its size: nothing that changes during the scan may resize it
            Shown += (s, e) => { var sz = Size; AutoSize = false; MinimumSize = MaximumSize = sz; };

            var existing = Scanner.DefaultLog();
            if (File.Exists(existing)) { logPath = existing; open.Enabled = true; }

            FormClosing += (s, e) =>
            {
                if (!running) return;
                e.Cancel = true;
                MessageBox.Show(this, "The scan is still running. Please wait until it is finished.", Text, MessageBoxButtons.OK, MessageBoxIcon.Information);
            };
        }


        /// <summary>Ticks the modules of the chosen profile ("Custom" changes nothing).</summary>
        void ApplyProfile()
        {
            if (profile.SelectedIndex < 0 || profile.SelectedIndex >= Scanner.Profiles.Length) return;
            var sel = Scanner.ProfileModules(Scanner.Profiles[profile.SelectedIndex].Id);
            applying = true;
            try { foreach (var kv in mods) kv.Value.Checked = sel.Contains(kv.Key); }
            finally { applying = false; }
        }

        /// <summary>The profile whose modules are ticked, or "Custom".</summary>
        void ShowProfile()
        {
            var id = MatchingProfile();
            int i = Array.FindIndex(Scanner.Profiles, p => p.Id == id);
            applying = true;
            try { profile.SelectedIndex = i >= 0 ? i : profile.Items.IndexOf(Custom); }
            finally { applying = false; }
        }

        /// <summary>The id of the profile with exactly the ticked modules, or null.</summary>
        string MatchingProfile()
        {
            var sel = new HashSet<string>(mods.Where(kv => kv.Value.Checked).Select(kv => kv.Key), StringComparer.OrdinalIgnoreCase);
            return Scanner.Profiles.Where(p => sel.SetEquals(p.Modules)).Select(p => p.Id).FirstOrDefault();
        }

        void StartScan()
        {
            var sel = mods.Where(kv => kv.Value.Checked).Select(kv => kv.Key).ToList();
            if (sel.Count == 0) { MessageBox.Show(this, "Select at least one thing to scan.", Text, MessageBoxButtons.OK, MessageBoxIcon.Information); return; }
            var prof = MatchingProfile();
            var o = new Options
            {
                Days = (int)days.Value,
                Whitelist = whitelist.Checked,
                NoHash = !hash.Checked,
                Profile = prof ?? "default",
                Modules = prof != null ? null : new HashSet<string>(sel, StringComparer.OrdinalIgnoreCase)
            };
            SetRunning(true);
            var sw = Stopwatch.StartNew();
            Task.Run(() => Scanner.Run(o, (t, i, n) => BeginInvoke((Action)(() =>
            {
                bar.Maximum = n; bar.Value = Math.Min(i, n);
                status.Text = i < n ? $"Scanning ({i + 1}/{n}): {t} ..." : t + " ...";
            })))).ContinueWith(t => BeginInvoke((Action)(() =>
            {
                SetRunning(false);
                if (t.IsFaulted)
                {
                    var ex = t.Exception?.GetBaseException();
                    status.Text = "Failed: " + ex?.Message;
                    MessageBox.Show(this, "The scan failed:\r\n" + ex, Text, MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }
                logPath = t.Result; open.Enabled = true;
                bar.Value = bar.Maximum;
                status.Text = $"Done in {sw.Elapsed.TotalSeconds:N0} s. Log saved to:\r\n{logPath}";
                Program.OpenLog(logPath);
            })));
        }

        void SetRunning(bool r)
        {
            running = r;
            scan.Enabled = !r; open.Enabled = !r && logPath != null;
            whitelist.Enabled = hash.Enabled = days.Enabled = profile.Enabled = !r;
            foreach (var cb in mods.Values) cb.Enabled = !r;
            UseWaitCursor = r;
            if (r) { bar.Value = 0; status.Text = "Starting ..."; }
        }
    }
}
