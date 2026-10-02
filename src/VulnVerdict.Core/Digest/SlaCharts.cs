using System.Globalization;
using System.Net;
using System.Text;
using VulnVerdict.Core.Data;

namespace VulnVerdict.Core.Digest;

/// <summary>
/// The SLA trend charts as inline SVG, built on the server: no script, so they work under the console's content
/// security policy, in the printed view and in a saved page. Text and grid lines use currentColor, so they follow the
/// page in light and dark; series colours are CSS variables with fallbacks (see <see cref="Css"/>). Every mark carries
/// a title (the browser's own tooltip), and every chart's numbers are also in the table beside it.
/// </summary>
public static class SlaCharts
{
    /// <summary>
    /// Series colours, chosen to stay distinguishable with the common colour-vision deficiencies in both themes. Tiers
    /// keep the same colour in every chart. Include once on a page that shows charts.
    /// </summary>
    public const string Css = """
        .vv-chart{--vv-s1:#2a78d6;--vv-s2:#eb6834;--vv-s3:#1baf7a;--vv-surface:var(--panel,var(--bg,#fff));margin:0}
        .vv-chart svg{display:block;width:100%;height:auto;font-family:inherit}
        .vv-chart figcaption{font-weight:700;font-size:13px;margin:0 0 2px}
        .vv-chart .vv-legend{display:flex;gap:14px;flex-wrap:wrap;font-size:12px;margin:0 0 2px;padding:0;list-style:none}
        .vv-chart .vv-legend i{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:5px}
        @media (prefers-color-scheme:dark){:root:not([data-theme="light"]) .vv-chart{--vv-s1:#3987e5;--vv-s2:#d95926;--vv-s3:#199e70}}
        :root[data-theme="dark"] .vv-chart{--vv-s1:#3987e5;--vv-s2:#d95926;--vv-s3:#199e70}
        @media print{.vv-chart{--vv-s1:#2a78d6;--vv-s2:#eb6834;--vv-s3:#1baf7a}}

        """;

    private const int W = 640, H = 230, Left = 44, Right = 40, Top = 12, Bottom = 30;
    private static readonly string[] Slots = { "var(--vv-s1,#2a78d6)", "var(--vv-s2,#eb6834)", "var(--vv-s3,#1baf7a)" };

    public sealed record Series(string Name, int Slot, IReadOnlyList<double?> Values);

    private static string F(double v) => v.ToString("0.##", CultureInfo.InvariantCulture);
    private static string E(string s) => WebUtility.HtmlEncode(s);

    /// <summary>A round step that gives about four ticks up to max: 1, 2 or 5 times a power of ten.</summary>
    public static double NiceStep(double max, int ticks = 4)
    {
        if (max <= 0) return 1;
        var raw = max / ticks;
        var pow = Math.Pow(10, Math.Floor(Math.Log10(raw)));
        var f = raw / pow;
        return (f <= 1 ? 1 : f <= 2 ? 2 : f <= 5 ? 5 : 10) * pow;
    }

    private static (double Max, double Step) Scale(IEnumerable<double?> values, double? fixedMax)
    {
        if (fixedMax is { } m) return (m, m / 4);
        var max = values.Where(v => v.HasValue).Select(v => v!.Value).DefaultIfEmpty(0).Max();
        var step = NiceStep(max <= 0 ? 4 : max);
        return (Math.Max(step * Math.Ceiling(max / step), step), step);
    }

    private static void Frame(StringBuilder sb, string title, string summary, IReadOnlyList<Series> series, bool legend)
    {
        sb.Append("<figure class=\"vv-chart\"><figcaption>" + E(title) + "</figcaption>");
        if (legend)
        {
            sb.Append("<ul class=\"vv-legend\">");
            foreach (var s in series) sb.Append("<li><i style=\"background:" + Slots[s.Slot] + "\"></i>" + E(s.Name) + "</li>");
            sb.Append("</ul>");
        }
        sb.Append("<svg viewBox=\"0 0 " + W + " " + H + "\" role=\"img\" aria-label=\"" + E(title + ". " + summary) + "\" xmlns=\"http://www.w3.org/2000/svg\">");
    }

    private static void Axes(StringBuilder sb, IReadOnlyList<string> labels, double max, double step, string unit)
    {
        var plotH = H - Top - Bottom;
        for (var v = 0.0; v <= max + step / 1000; v += step)
        {
            var y = Top + plotH - v / max * plotH;
            sb.Append("<line x1=\"" + Left + "\" x2=\"" + (W - Right) + "\" y1=\"" + F(y) + "\" y2=\"" + F(y) + "\" stroke=\"currentColor\" stroke-opacity=\"" + (v == 0 ? ".45" : ".14") + "\" stroke-width=\"1\"/>");
            sb.Append("<text x=\"" + (Left - 6) + "\" y=\"" + F(y + 3.5) + "\" text-anchor=\"end\" font-size=\"10.5\" fill=\"currentColor\" fill-opacity=\".75\">" + F(v) + unit + "</text>");
        }
        var every = labels.Count > 14 ? (int)Math.Ceiling(labels.Count / 13.0) : 1;
        for (var i = 0; i < labels.Count; i++)
        {
            if ((labels.Count - 1 - i) % every != 0) continue;
            sb.Append("<text x=\"" + F(X(i, labels.Count)) + "\" y=\"" + (H - Bottom + 15) + "\" text-anchor=\"middle\" font-size=\"10.5\" fill=\"currentColor\" fill-opacity=\".75\">" + E(labels[i]) + "</text>");
        }
    }

    /// <summary>The centre of slot i of n along the x axis.</summary>
    private static double X(int i, int n) => Left + (W - Left - Right) * (i + 0.5) / Math.Max(n, 1);

    private static string Empty(string title, string message) =>
        "<figure class=\"vv-chart\"><figcaption>" + E(title) + "</figcaption><p class=\"muted\" style=\"margin:4px 0 12px\">" + E(message) + "</p></figure>";

    /// <summary>Lines with a dot at every value. A missing value breaks the line rather than dropping to zero.</summary>
    public static string Line(string title, IReadOnlyList<string> labels, IReadOnlyList<Series> series, string unit, string valueSuffix, double? fixedMax = null, string emptyMessage = "Nothing to show yet.")
    {
        if (series.All(s => s.Values.All(v => v is null))) return Empty(title, emptyMessage);
        var (max, step) = Scale(series.SelectMany(s => s.Values), fixedMax);
        var plotH = H - Top - Bottom;
        var sb = new StringBuilder();
        Frame(sb, title, series.Count + " series over " + labels.Count + " weeks; the numbers are in the table.", series, series.Count > 1);
        Axes(sb, labels, max, step, unit);
        foreach (var s in series)
        {
            var path = new StringBuilder();
            var pen = false;
            for (var i = 0; i < s.Values.Count; i++)
            {
                if (s.Values[i] is not { } v) { pen = false; continue; }
                path.Append((pen ? "L" : "M") + F(X(i, labels.Count)) + " " + F(Top + plotH - Math.Min(v, max) / max * plotH));
                pen = true;
            }
            sb.Append("<path d=\"" + path + "\" fill=\"none\" stroke=\"" + Slots[s.Slot] + "\" stroke-width=\"2\" stroke-linejoin=\"round\" stroke-linecap=\"round\"/>");
        }
        // dots after every line, each ringed in the surface colour so it stays readable where lines cross
        foreach (var s in series)
            for (var i = 0; i < s.Values.Count; i++)
            {
                if (s.Values[i] is not { } v) continue;
                sb.Append("<circle cx=\"" + F(X(i, labels.Count)) + "\" cy=\"" + F(Top + plotH - Math.Min(v, max) / max * plotH) + "\" r=\"4\" fill=\"" + Slots[s.Slot] + "\" stroke=\"var(--vv-surface,#fff)\" stroke-width=\"2\"><title>"
                          + E(s.Name + ", " + labels[i] + ": " + F(v) + valueSuffix) + "</title></circle>");
            }
        // one series: say the latest value at the end of the line, in text colour
        if (series.Count == 1)
        {
            var s = series[0];
            var last = Enumerable.Range(0, s.Values.Count).LastOrDefault(i => s.Values[i].HasValue, -1);
            if (last >= 0)
            {
                var v = s.Values[last]!.Value;
                var y = Top + plotH - Math.Min(v, max) / max * plotH;
                // to the right of the last point, in the margin kept for it, so it never sits on the line
                sb.Append("<text x=\"" + F(X(last, labels.Count) + 9) + "\" y=\"" + F(y + 4) + "\" font-size=\"11\" font-weight=\"600\" fill=\"currentColor\">" + v.ToString("0.#", CultureInfo.InvariantCulture) + valueSuffix + "</text>");
            }
        }
        sb.Append("</svg></figure>");
        return sb.ToString();
    }

    /// <summary>Side-by-side columns per week, at most 24 wide, rounded at the top and square on the baseline.</summary>
    public static string Columns(string title, IReadOnlyList<string> labels, IReadOnlyList<Series> series, string emptyMessage = "Nothing to show yet.")
    {
        if (series.All(s => s.Values.All(v => v is null or 0))) return Empty(title, emptyMessage);
        var (max, step) = Scale(series.SelectMany(s => s.Values), null);
        var plotH = H - Top - Bottom;
        var slot = (W - Left - Right) / (double)Math.Max(labels.Count, 1);
        const double gap = 2;
        var bar = Math.Min(24, (slot * 0.7 - gap * (series.Count - 1)) / series.Count);
        var sb = new StringBuilder();
        Frame(sb, title, series.Count + " series over " + labels.Count + " weeks; the numbers are in the table.", series, series.Count > 1);
        Axes(sb, labels, max, step, "");
        for (var i = 0; i < labels.Count; i++)
        {
            var groupLeft = X(i, labels.Count) - (bar * series.Count + gap * (series.Count - 1)) / 2;
            for (var k = 0; k < series.Count; k++)
            {
                if (series[k].Values[i] is not { } v || v <= 0) continue;
                var h = v / max * plotH;
                var x = groupLeft + k * (bar + gap);
                var y = Top + plotH - h;
                var r = Math.Min(4, Math.Min(h, bar / 2));
                sb.Append("<path d=\"M" + F(x) + " " + F(Top + plotH) + "V" + F(y + r) + "Q" + F(x) + " " + F(y) + " " + F(x + r) + " " + F(y) + "H" + F(x + bar - r) + "Q" + F(x + bar) + " " + F(y) + " " + F(x + bar) + " " + F(y + r) + "V" + F(Top + plotH) + "Z\" fill=\"" + Slots[series[k].Slot] + "\"><title>"
                          + E(series[k].Name + ", " + labels[i] + ": " + F(v)) + "</title></path>");
            }
        }
        sb.Append("</svg></figure>");
        return sb.ToString();
    }

    private static List<string> Labels(SlaReport r) => r.Weeks.Select(w => w.Week.Start.ToString("d MMM", CultureInfo.InvariantCulture)).ToList();

    /// <summary>Median days to fix per tier, by the week the verdict closed.</summary>
    public static string TimeToFix(SlaReport r) => Line("Median days to fix, by week closed", Labels(r),
        SlaMath.Tiers.Select((t, i) => new Series(t.Plain(), i, r.Weeks.Select(w => w.Tiers[t].MedianDays).ToList())).ToList(), "", " days",
        emptyMessage: "Nothing has closed in these weeks.");

    public static string WithinSla(SlaReport r) => Line("Closed inside the fix window", Labels(r),
        new[] { new Series("Closed inside the fix window", 0, r.Weeks.Select(w => w.WithinSlaPercent).ToList()) }, "%", "%", fixedMax: 100,
        emptyMessage: "Nothing has closed in these weeks.");

    public static string Overdue(SlaReport r) => Line("Overdue at the end of each week", Labels(r),
        new[] { new Series("Overdue", 0, r.Weeks.Select(w => (double?)w.OverdueAtEnd).ToList()) }, "", "",
        emptyMessage: "The worker records this once a day; the first numbers appear within the hour.");

    public static string OpenedClosed(SlaReport r) => Columns("Opened and closed per week", Labels(r), new[]
    {
        new Series("Opened", 0, r.Weeks.Select(w => (double?)w.Opened).ToList()),
        new Series("Closed", 1, r.Weeks.Select(w => (double?)w.Closed).ToList()),
    }, "Nothing was opened or closed in these weeks.");
}
