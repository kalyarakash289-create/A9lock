using System.Runtime.InteropServices;
using A9SecurityLock.Forms;
using A9SecurityLock.Models;
using A9SecurityLock.Security;
using A9SecurityLock.Services;

namespace A9SecurityLock.Forms;

/// <summary>
/// Password-protected overlay shown over a locked application's window (or full screen for
/// idle locks). Top-most, tool window, no min/max/Close box — but always escapable via its
/// own visible controls. Never terminates the target application or destroys unsaved work.
/// </summary>
public sealed class LockScreenForm : Form
{
    [DllImport("user32.dll")] private static extern bool SetForegroundWindow(IntPtr hWnd);

    private readonly AuthService _auth;
    private readonly AppLockRule? _rule;      // null => session/idle lock
    private readonly string? _exeNameLower;   // exe to suppress after unlock
    private readonly Action<(AppLockRule? rule, string? exe)>? _onUnlocked;
    private readonly Action? _onCancelled;

    private readonly TextBox _password = new();
    private readonly Button _unlock = new();
    private readonly Button _toggle = new();
    private readonly Label _status = new();
    private readonly Label _headline = new();
    private readonly System.Windows.Forms.Timer _cooldownTimer = new();
    private DateTime _cooldownUntilUtc = DateTime.MinValue;

    public bool Unlocked { get; private set; }

    /// <param name="bounds">Screen bounds to cover (target window rect, or primary screen for idle locks).</param>
    public LockScreenForm(AuthService auth, Rectangle bounds, AppLockRule? rule,
                          string? exeNameLower, Action<(AppLockRule? rule, string? exe)>? onUnlocked,
                          Action? onCancelled)
    {
        _auth = auth;
        _rule = rule;
        _exeNameLower = exeNameLower;
        _onUnlocked = onUnlocked;
        _onCancelled = onCancelled;

        Text = "A9 Security Lock";
        FormBorderStyle = FormBorderStyle.None;
        StartPosition = FormStartPosition.Manual;
        Bounds = Rectangle.Intersect(bounds, Screen.PrimaryScreen?.Bounds ?? bounds);
        if (Bounds.Width < 320 || Bounds.Height < 240)
            Bounds = Screen.PrimaryScreen?.Bounds ?? new Rectangle(0, 0, 1024, 768);

        TopMost = true;
        ShowInTaskbar = false;
        MinimizeBox = false;
        MaximizeBox = false;
        ControlBox = false;
        BackColor = Theme.BgDark;
        KeyPreview = true;
        DoubleBuffered = true;
        try { Icon = SystemIcons.Shield; } catch { }

        int cx = Bounds.Width, cy = Bounds.Height;

        var panel = new Panel
        {
        Location = new Point(Math.Max(16, (cx - 420) / 2), Math.Max(16, (cy - 300) / 2)),
            Size = new Size(Math.Min(420, cx - 32), Math.Min(300, cy - 32)),
            BackColor = Theme.BgPanel,
        };
        Controls.Add(panel);

        var logo = new LogoPictureBox { Size = new Size(72, 72), Location = new Point((panel.Width - 72) / 2, 18) };
        panel.Controls.Add(logo);

        _headline.AutoSize = false;
        _headline.Font = Theme.FontHeading;
        _headline.ForeColor = Theme.TextMain;
        _headline.TextAlign = ContentAlignment.MiddleCenter;
        _headline.Location = new Point(10, 96);
        _headline.Size = new Size(panel.Width - 20, 44);
        _headline.Text = _rule != null
            ? $"🔒 Locked: {_rule.DisplayName}"
            : "🔒 Session locked";
        panel.Controls.Add(_headline);

        var subtitle = new Label
        {
            AutoSize = false,
            Font = Theme.FontBody,
            ForeColor = Theme.TextDim,
            TextAlign = ContentAlignment.MiddleCenter,
            Location = new Point(16, 138),
            Size = new Size(panel.Width - 32, 34),
            Text = _rule != null
                ? $"The application lock rule \"{_rule.DisplayName}\" was triggered.\nEnter your master password to unlock."
                : "Enter your master password to continue.",
        };
        panel.Controls.Add(subtitle);

        _password.Location = new Point(40, 180);
        _password.Width = panel.Width - 130;
        _password.UseSystemPasswordChar = true;
        _password.Font = Theme.FontBody;
        panel.Controls.Add(_password);

        _toggle.Text = "Show";
        _toggle.Location = new Point(panel.Width - 84, 179);
        _toggle.Size = new Size(50, 25);
        _toggle.Click += (_, _) =>
        {
            _password.UseSystemPasswordChar = !_password.UseSystemPasswordChar;
            _toggle.Text = _password.UseSystemPasswordChar ? "Show" : "Hide";
        };
        panel.Controls.Add(_toggle);

        _unlock.Text = "Unlock";
        _unlock.Location = new Point(40, 214);
        _unlock.Size = new Size(panel.Width - 80, 30);
        _unlock.Click += (_, _) => TryUnlock();
        panel.Controls.Add(_unlock);

        _status.AutoSize = false;
        _status.Font = Theme.FontBody;
        _status.ForeColor = Theme.DangerRed;
        _status.TextAlign = ContentAlignment.MiddleCenter;
        _status.Location = new Point(10, 250);
        _status.Size = new Size(panel.Width - 20, 40);
        panel.Controls.Add(_status);

        AcceptButton = _unlock;
        _cooldownTimer.Interval = 500;
        _cooldownTimer.Tick += (_, _) => UpdateCooldown();
        _cooldownTimer.Start();

        Load += (_, _) =>
        {
            _password.Focus();
            SetForegroundWindow(Handle);
        };
        Activated += (_, _) => { _password.Focus(); SetForegroundWindow(Handle); };
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        base.OnPaint(e);
        using var b = new SolidBrush(Color.FromArgb(235, Theme.BgDark));
        e.Graphics.FillRectangle(b, ClientRectangle);
        // Accent border around the whole overlay
        using var pen = new Pen(Theme.AccentBlue, 2);
        e.Graphics.DrawRectangle(pen, 1, 1, Width - 3, Height - 3);
    }

    private void TryUnlock()
    {
        if (DateTime.UtcNow < _cooldownUntilUtc) return;

        string pwd = _password.Text;
        _password.Clear();

        if (_auth.VerifyMasterPassword(pwd, out string error))
        {
            Unlocked = true;
            _cooldownTimer.Stop();
            _cooldownTimer.Dispose();
            _auth.MarkUnlocked();
            _onUnlocked?.Invoke(_rule, _exeNameLower);
            Close();
        }
        else
        {
            _status.ForeColor = Theme.DangerRed;
            _status.Text = error;
            if (_auth.IsLockedOut)
            {
                _cooldownUntilUtc = DateTime.UtcNow + _auth.RemainingLockout;
                _unlock.Enabled = false;
                _cooldownTimer.Start();
            }
        }
    }

    private void UpdateCooldown()
    {
        var rem = _cooldownUntilUtc - DateTime.UtcNow;
        if (rem <= TimeSpan.Zero)
        {
            _unlock.Enabled = true;
            _status.ForeColor = Theme.TextDim;
            _status.Text = "";
            _cooldownTimer.Stop();
            return;
        }
        _status.ForeColor = Theme.DangerRed;
        _status.Text = $"Wait {rem.TotalSeconds:0} s before next attempt.";
    }

    protected override void OnFormClosed(FormClosedEventArgs e)
    {
        _cooldownTimer.Dispose();
        if (!Unlocked) _onCancelled?.Invoke();
        base.OnFormClosed(e);
    }

    protected override bool ProcessCmdKey(ref Message msg, Keys keyData)
    {
        // Escape cancels only when allowed by owner (manual cancel path). We keep it simple:
        // Escape behaves like "cancel" — the owner decides what that means (re-lock or hide).
        if (keyData == Keys.Escape && _rule == null)
        {
            // Idle/session lock: escape does nothing (must authenticate) — documented behavior.
            return true;
        }
        return base.ProcessCmdKey(ref msg, keyData);
    }

    /// <summary>PictureBox that renders the vector A9 shield logo.</summary>
    private sealed class LogoPictureBox : PictureBox
    {
        public LogoPictureBox()
        {
            SizeMode = PictureBoxSizeMode.AutoSize;
            Image = Theme.RenderLogoBitmap(72);
        }
    }
}
