using System.Drawing.Drawing2D;

namespace A9SecurityLock.Forms;

/// <summary>
/// Original A9 brand assets drawn with vector paths (no third-party images).
/// Provides: logo painting, rounded-rectangle helpers, and an ICO encoder used
/// by scripts/generate-icon.ps1 and the app itself at runtime.
/// </summary>
public static class Theme
{
    // ----- palette -----
    public static readonly Color BgDark     = Color.FromArgb(18, 20, 24);    // charcoal black
    public static readonly Color BgPanel    = Color.FromArgb(27, 30, 36);    // panel
    public static readonly Color BgSidebar  = Color.FromArgb(22, 25, 30);
    public static readonly Color AccentBlue = Color.FromArgb(38, 132, 255);
    public static readonly Color AccentCyan = Color.FromArgb(64, 224, 255);
    public static readonly Color TextMain   = Color.FromArgb(232, 236, 242);
    public static readonly Color TextDim    = Color.FromArgb(150, 158, 170);
    public static readonly Color DangerRed  = Color.FromArgb(232, 76, 76);
    public static readonly Color SuccessGrn = Color.FromArgb(66, 190, 120);
    public static readonly Color BorderSoft = Color.FromArgb(52, 58, 68);

    public static Font FontTitle => new("Segoe UI", 16F, FontStyle.Bold);
    public static Font FontHeading => new("Segoe UI", 11F, FontStyle.Bold);
    public static Font FontBody => new("Segoe UI", 9.5F);
    public static Font FontMono => new("Consolas", 9F);

    /// <summary>Rounded rectangle path helper.</summary>
    public static GraphicsPath RoundedRect(Rectangle r, int radius)
    {
        int d = Math.Min(radius * 2, Math.Min(r.Width, r.Height));
        var p = new GraphicsPath();
        if (d <= 0) { p.AddRectangle(r); p.CloseFigure(); return p; }
        p.AddArc(r.X, r.Y, d, d, 180, 90);
        p.AddArc(r.Right - d, r.Y, d, d, 270, 90);
        p.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
        p.AddArc(r.X, r.Bottom - d, d, d, 90, 90);
        p.CloseFigure();
        return p;
    }

    public static void FillRounded(Graphics g, Rectangle r, int radius, Color fill, Color? border = null)
    {
        using var path = RoundedRect(r, radius);
        using var b = new SolidBrush(fill);
        g.FillPath(b, path);
        if (border.HasValue)
        {
            using var pen = new Pen(border.Value, 1f);
            g.DrawPath(pen, path);
        }
    }

    /// <summary>
    /// Paints the original A9 logo: a shield outline containing a stylized "A9" monogram
    /// and a keyhole dot — all built from vector primitives (original artwork).
    /// </summary>
    public static void PaintLogo(Graphics g, Rectangle bounds, bool lightOnDark = true)
    {
        g.SmoothingMode = SmoothingMode.AntiAlias;
        float w = bounds.Width, h = bounds.Height;
        PointF Pt(float x, float y) => new(bounds.X + x * w, bounds.Y + y * h);

        // Shield outline
        using (var shield = new GraphicsPath())
        {
            shield.AddLines(new[]
            {
                Pt(0.50f, 0.02f), Pt(0.92f, 0.16f), Pt(0.92f, 0.50f),
                Pt(0.50f, 0.97f), Pt(0.08f, 0.50f), Pt(0.08f, 0.16f),
            });
            shield.CloseFigure();

            using var grad = new LinearGradientBrush(
                new RectangleF(bounds.X, bounds.Y, w, h),
                        AccentBlue, AccentCyan, 45f);
            using var fillB = new SolidBrush(Color.FromArgb(lightOnDark ? 34 : 24, 40, 52));
            g.FillPath(fillB, shield);
            using var pen = new Pen(grad, Math.Max(2f, w * 0.035f));
            g.DrawPath(pen, shield);
        }

        // "A" glyph as strokes
        using (var aPen = new Pen(AccentCyan, Math.Max(2f, w * 0.06f)) { StartCap = LineCap.Round, EndCap = LineCap.Round })
        {
            g.DrawLine(aPen, Pt(0.30f, 0.62f), Pt(0.42f, 0.30f));
            g.DrawLine(aPen, Pt(0.42f, 0.30f), Pt(0.54f, 0.62f));
            g.DrawLine(aPen, Pt(0.35f, 0.52f), Pt(0.49f, 0.52f));
        }

        // "9" glyph: circle + tail
        using (var ninePen = new Pen(AccentBlue, Math.Max(2f, w * 0.06f)) { StartCap = LineCap.Round, EndCap = LineCap.Round })
        {
            float cx = 0.66f, cy = 0.40f, rr = 0.085f;
            g.DrawEllipse(ninePen,
                bounds.X + (cx - rr) * w, bounds.Y + (cy - rr) * h,
                rr * 2 * w, rr * 2 * h);
            g.DrawLine(ninePen, Pt(0.745f, 0.40f), Pt(0.70f, 0.62f));
        }

        // Keyhole dot under the monogram (locks the "security" idea into the mark)
        using (var dotB = new SolidBrush(AccentCyan))
        {
            float d = Math.Max(3f, w * 0.05f);
            g.FillEllipse(dotB, bounds.X + 0.50f * w - d / 2, bounds.Y + 0.74f * h, d, d);
        }
    }

    /// <summary>
    /// Renders the logo to a Bitmap at the given size on a transparent background.
    /// Used both for window icons and for building the .ico file.
    /// </summary>
    public static Bitmap RenderLogoBitmap(int size)
    {
        var bmp = new Bitmap(size, size);
        using var g = Graphics.FromImage(bmp);
        g.Clear(Color.Transparent);
        PaintLogo(g, new Rectangle(1, 1, size - 2, size - 2));
        return bmp;
    }

    /// <summary>
    /// Writes a multi-size ICO file (256/64/48/32/16) built from rendered PNG frames.
    /// ICO allows PNG-compressed entries since Vista — perfect for our sizes.
    /// </summary>
    public static void WriteIcoFile(string path, int[] sizes)
    {
        using var ms = new MemoryStream();
        using var bw = new BinaryWriter(ms);

        // Encode all PNG frames first so we know offsets.
        var pngs = sizes.Select(s =>
        {
            using var b = RenderLogoBitmap(s);
            using var pm = new MemoryStream();
            b.Save(pm, System.Drawing.Imaging.ImageFormat.Png);
            return pm.ToArray();
        }).ToList();

        bw.Write((ushort)0);            // reserved
        bw.Write((ushort)1);            // type: icon
        bw.Write((ushort)sizes.Count);  // count

        uint offset = (uint)(6 + 16 * sizes.Count);
        for (int i = 0; i < sizes.Count; i++)
        {
            int s = sizes[i];
            bw.Write((byte)(s >= 256 ? 0 : s)); // width  (0 = 256)
            bw.Write((byte)(s >= 256 ? 0 : s)); // height
            bw.Write((byte)0);                  // colors
            bw.Write((byte)0);                  // reserved
            bw.Write((ushort)1);                // planes
            bw.Write((ushort)32);               // bpp
            bw.Write((uint)pngs[i].Length);     // size
            bw.Write(offset);                   // offset
            offset += (uint)pngs[i].Length;
        }

        foreach (var p in pngs) bw.Write(p);
        bw.Flush();
        File.WriteAllBytes(path, ms.ToArray());
    }
}
