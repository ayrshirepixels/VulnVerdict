using System.Globalization;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace VulnVerdict.Core.Services;

/// <summary>
/// Once a day, asks GitHub which release is the latest, so the console can say when a newer one is out (most are
/// security fixes). Only the release list is fetched; nothing about this install is sent. Off when Settings say so, and
/// on bundle-fed (air-gapped) installs. Also reads what deploy/auto-update.sh recorded about its last attempt.
/// </summary>
public sealed class UpdateCheckService
{
    public const string ReleasesUrl = "https://api.github.com/repos/ayrshirepixels/VulnVerdict/releases/latest";
    public static readonly TimeSpan Interval = TimeSpan.FromHours(24);
    /// <summary>A failed automatic update stays on screen this long, a successful one is mentioned in the digest this long.</summary>
    public static readonly TimeSpan AutoUpdateShownFor = TimeSpan.FromDays(7);

    public sealed record LatestRelease(string Version, string Url, DateTime CheckedAt);
    /// <summary>What deploy/auto-update.sh wrote: ok, rolled-back or failed, the two versions and when.</summary>
    public sealed record AutoUpdateResult(string Result, string From, string To, DateTime At, string? Message);

    private readonly SettingsService _settings;
    private readonly IHttpClientFactory _http;
    private readonly IServiceProvider _sp;
    private readonly ILogger<UpdateCheckService> _log;

    public UpdateCheckService(SettingsService settings, IHttpClientFactory http, IServiceProvider sp, ILogger<UpdateCheckService> log)
    {
        _settings = settings; _http = http; _sp = sp; _log = log;
    }

    public async Task CheckIfDueAsync(CancellationToken ct)
    {
        var s = await _settings.LoadAsync(ct);
        if (!s.UpdateCheck) return;
        if (_sp.GetService(typeof(BundleService)) is BundleService bundles && await bundles.IsBundleModeAsync(ct)) return;
        var last = Parse<LatestRelease>(await _settings.GetStateAsync(SettingsService.Keys.UpdateLatest, ct));
        if (last is not null && DateTime.UtcNow - last.CheckedAt < Interval) return;
        try
        {
            var client = _http.CreateClient("feeds");
            using var resp = await client.GetAsync(ReleasesUrl, ct);
            resp.EnsureSuccessStatusCode();
            using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct));
            var tag = doc.RootElement.GetProperty("tag_name").GetString() ?? "";
            var url = doc.RootElement.TryGetProperty("html_url", out var u) ? u.GetString() ?? "" : "";
            var version = tag.TrimStart('v', 'V');
            if (ParseVersion(version) is null) throw new InvalidOperationException("unexpected release tag " + tag);
            await _settings.SetStateAsync(SettingsService.Keys.UpdateLatest, JsonSerializer.Serialize(new LatestRelease(version, url, DateTime.UtcNow)), ct);
        }
        catch (Exception ex) when (ex is HttpRequestException or JsonException or InvalidOperationException or KeyNotFoundException or TaskCanceledException)
        {
            // not worth an alert: an offline or firewalled install simply never hears of a release
            _log.LogInformation("Release check skipped: {Message}", ex.Message);
        }
    }

    public async Task<LatestRelease?> LatestAsync(CancellationToken ct = default) =>
        (await _settings.LoadAsync(ct)).UpdateCheck ? Parse<LatestRelease>(await _settings.GetStateAsync(SettingsService.Keys.UpdateLatest, ct)) : null;

    public async Task<AutoUpdateResult?> AutoUpdateAsync(CancellationToken ct = default) =>
        ParseAutoUpdate(await _settings.GetStateAsync(SettingsService.Keys.UpdateAuto, ct));

    // ------------------------------------------------------------------ pure, tested

    /// <summary>The release is newer than the running one. "dev" and anything unreadable is never behind.</summary>
    public static bool IsNewer(string latest, string current) =>
        ParseVersion(latest) is { } l && ParseVersion(current) is { } c && l.CompareTo(c) > 0;

    /// <summary>The release is a patch of the running one (1.2.3 to 1.2.4): the only kind auto-update.sh applies.</summary>
    public static bool IsPatch(string latest, string current) =>
        ParseVersion(latest) is { } l && ParseVersion(current) is { } c && l.Major == c.Major && l.Minor == c.Minor && l.Build > c.Build;

    public static Version? ParseVersion(string? v) =>
        v is not null && System.Text.RegularExpressions.Regex.IsMatch(v.Trim(), @"^\d+\.\d+\.\d+$") && Version.TryParse(v.Trim(), out var parsed) ? parsed : null;

    /// <summary>"Release 1.2.4 is out" for the banner, worded for how this install updates.</summary>
    public static HealthNotices.Notice? AvailableNotice(LatestRelease? latest, string current, string? role)
    {
        if (latest is null || !IsNewer(latest.Version, current)) return null;
        var how = role is "web" or "worker"
            ? IsPatch(latest.Version, current) ? " Run ./update.sh in the install folder, or turn on automatic patch updates (VV_AUTO_UPDATE=patch)." : " Run ./update.sh " + latest.Version + " in the install folder after reading what changed."
            : " Pull the :" + latest.Version + "-allinone image and recreate the container on the same volume.";
        return new HealthNotices.Notice(false, "VulnVerdict " + latest.Version + " is available; this console runs " + current + "." + how, latest.Url);
    }

    /// <summary>A failed or rolled-back automatic update, for the banner while it is recent.</summary>
    public static HealthNotices.Notice? AutoUpdateNotice(AutoUpdateResult? r, DateTime utcNow)
    {
        if (r is null || r.Result == "ok" || utcNow - r.At > AutoUpdateShownFor) return null;
        var what = r.Result == "rolled-back" ? "did not come up and was rolled back to " + r.From : "could not run";
        return new HealthNotices.Notice(true, "The automatic update from " + r.From + " to " + r.To + " on " + r.At.ToString("d MMM HH:mm", CultureInfo.InvariantCulture) + " UTC " + what
            + (string.IsNullOrWhiteSpace(r.Message) ? "." : ": " + r.Message.TrimEnd('.') + ".") + " Run ./update.sh by hand to see why.", "https://github.com/ayrshirepixels/VulnVerdict/blob/main/docs/install.md#automatic-patch-updates");
    }

    /// <summary>One line for the digest: an automatic update in the last week, either way.</summary>
    public static string? DigestLine(AutoUpdateResult? r, DateTime utcNow)
    {
        if (r is null || utcNow - r.At > AutoUpdateShownFor) return null;
        var when = r.At.ToString("d MMM", CultureInfo.InvariantCulture);
        return r.Result == "ok"
            ? "Updated automatically from " + r.From + " to " + r.To + " on " + when + "."
            : "The automatic update to " + r.To + " on " + when + " " + (r.Result == "rolled-back" ? "was rolled back" : "failed") + "; the console still runs " + r.From + ".";
    }

    /// <summary>auto-update.sh writes "result|from|to|ISO time|message" into a settings row through psql.</summary>
    public static AutoUpdateResult? ParseAutoUpdate(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;
        var p = raw.Split('|', 5);
        if (p.Length < 4 || p[0] is not ("ok" or "rolled-back" or "failed")) return null;
        if (!DateTime.TryParse(p[3], CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var at)) return null;
        return new AutoUpdateResult(p[0], p[1], p[2], at, p.Length > 4 ? p[4] : null);
    }

    private static T? Parse<T>(string? json) where T : class
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try { return JsonSerializer.Deserialize<T>(json); } catch (JsonException) { return null; }
    }
}
