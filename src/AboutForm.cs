using System;
using System.Diagnostics;
using System.Drawing;
using System.Reflection;
using System.Windows.Forms;

namespace Spor
{
    /// <summary>About Spor: version, what it does, why antivirus programs may alert, author, license and project page.</summary>
    class AboutForm : Form
    {
        const string Url = "https://github.com/struppigel/Spor";

        public AboutForm()
        {
            Text = "About Spor";
            Font = SystemFonts.MessageBoxFont;
            AutoScaleMode = AutoScaleMode.Font;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = MinimizeBox = false;
            ShowIcon = ShowInTaskbar = false;
            StartPosition = FormStartPosition.CenterParent;
            AutoSize = true;
            AutoSizeMode = AutoSizeMode.GrowAndShrink;

            // icon left, text right; texts wrap at a width that scales with the font
            var root = new TableLayoutPanel { ColumnCount = 2, AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, Padding = new Padding(14), Location = new Point(0, 0) };
            root.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            root.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            Controls.Add(root);
            int wrap = Font.Height * 28;
            void Add(Control ctl) { root.RowCount++; root.RowStyles.Add(new RowStyle(SizeType.AutoSize)); root.Controls.Add(ctl, 1, root.RowCount - 1); }
            Label Para(string t, int top = 8) => new Label { Text = t, AutoSize = true, MaximumSize = new Size(wrap, 0), Margin = new Padding(0, top, 0, 0) };

            int px = Font.Height * 3;   // about 48 px at 100 %
            var logo = LoadLogo(px);
            if (logo != null)
            {
                var pic = new PictureBox { Image = logo, Size = new Size(px, px), SizeMode = PictureBoxSizeMode.Zoom, Margin = new Padding(0, 0, 14, 0) };
                root.Controls.Add(pic, 0, 0);
            }

            Add(new Label { Text = "Spor " + Scanner.Version, AutoSize = true, Font = new Font(Font.FontFamily, Font.Size * 1.5f, FontStyle.Bold), Margin = new Padding(0) });
            Add(Para("Forensic triage for malware removal helpers. Spor collects execution, download, persistence and remote-access " +
                      "evidence and writes it to one log file, Spor.txt.", 4));
            Add(Para("Spor only reads. It changes nothing on this PC and sends nothing: no update check, no telemetry. " +
                      "The log stays on this PC until you send it to someone."));
            Add(Para("Some antivirus programs alert on Spor, because it reads browser databases and other evidence through a " +
                      "shadow copy of the system drive, as some malware does. Download Spor only from the releases page " +
                      "and compare the SHA256 hash given there."));

            var asm = Assembly.GetExecutingAssembly();
            var copyright = asm.GetCustomAttribute<AssemblyCopyrightAttribute>()?.Copyright;
            Add(Para((string.IsNullOrEmpty(copyright) ? "" : copyright + "\r\n") + "MIT License", 12));

            var link = new LinkLabel { Text = Url.Substring("https://".Length), AutoSize = true, Margin = new Padding(0, 4, 0, 0) };
            link.LinkClicked += (s, e) => OpenUrl(Url);
            Add(link);

            var ok = new Button { Text = "OK", DialogResult = DialogResult.OK, AutoSize = true, MinimumSize = new Size(90, 28), Anchor = AnchorStyles.Right, Margin = new Padding(0, 14, 0, 0) };
            Add(ok);
            AcceptButton = CancelButton = ok;
        }

        /// <summary>The program logo at the given size, scaled down from the embedded 256 px Spor.png. (The exe's icon
        /// resource gives only 32 px, and Icon.ToBitmap garbles the PNG-compressed images in Spor.ico.)</summary>
        static Image LoadLogo(int px)
        {
            try
            {
                using (var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("Spor.Spor.png"))
                {
                    if (s == null) return null;
                    using (var src = Image.FromStream(s))
                    {
                        var bmp = new Bitmap(px, px);
                        using (var g = Graphics.FromImage(bmp))
                        {
                            g.InterpolationMode = System.Drawing.Drawing2D.InterpolationMode.HighQualityBicubic;
                            g.PixelOffsetMode = System.Drawing.Drawing2D.PixelOffsetMode.HighQuality;
                            g.DrawImage(src, 0, 0, px, px);
                        }
                        return bmp;
                    }
                }
            }
            catch { }
            return null;
        }

        /// <summary>Opens a web page in the default browser. Spor runs as administrator: through explorer.exe the
        /// browser starts with the user's normal rights, not elevated.</summary>
        static void OpenUrl(string url)
        {
            try { Process.Start(new ProcessStartInfo("explorer.exe", "\"" + url + "\"") { UseShellExecute = false }); }
            catch { }
        }
    }
}
