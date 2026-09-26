using Microsoft.Extensions.Logging;
using VulnVerdict.Core.Data;

namespace VulnVerdict.Core.Feeds;

/// <summary>
/// What a feed run produced. <paramref name="MoreSoon"/> asks the worker to run the feed again on its next pass instead of
/// waiting a whole interval, for work spread over several runs (a first load, or a history backfill).
/// </summary>
public sealed record FeedResult(int Records, string? Cursor, string? Note = null, bool MoreSoon = false);

public sealed class FeedContext
{
    public required VvDbContext Db { get; init; }
    public required HttpClient Http { get; init; }
    public required ILogger Log { get; init; }
    public required string DataDir { get; init; }
    public string? Cursor { get; init; }
    public Action<string> Progress { get; init; } = _ => { };
}

/// <summary>Every public feed implements this. Ingestion is idempotent and resumable.</summary>
public interface IFeed
{
    string Name { get; }
    string DisplayName { get; }
    int IntervalMinutes { get; }
    string Licence { get; }
    Task<FeedResult> RunAsync(FeedContext ctx, CancellationToken ct);
}

public static class FeedNames
{
    public const string CveList = "cvelist";
    public const string Kev = "kev";
    public const string Epss = "epss";
    public const string ExploitDb = "exploitdb";
    public const string Metasploit = "metasploit";
    public const string Nuclei = "nuclei";
}
