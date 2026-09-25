using VulnVerdict.Core.Data;

namespace VulnVerdict.Core.Feeds;

/// <summary>
/// When a feed counts as overdue: more than <see cref="Grace"/> past its own schedule. A flat 24 hours flagged every
/// daily feed for the minutes between its interval elapsing and the next run finishing (the Debian, Ubuntu and Red Hat
/// trackers take about a quarter of an hour), so the digest warned and the administrator was emailed daily for nothing.
/// </summary>
public static class FeedHealth
{
    /// <summary>Slack beyond the feed's interval for queueing behind other feeds, a restart, or a slow source.</summary>
    public static readonly TimeSpan Grace = TimeSpan.FromHours(6);

    public static TimeSpan Allowed(FeedStatus f) => TimeSpan.FromMinutes(Math.Max(f.IntervalMinutes, 60)) + Grace;

    /// <summary>Never succeeded, or last succeeded longer ago than its interval plus the grace period.</summary>
    public static bool IsOverdue(FeedStatus f, DateTime utcNow) => f.LastSuccess is null || utcNow - f.LastSuccess.Value > Allowed(f);
}
