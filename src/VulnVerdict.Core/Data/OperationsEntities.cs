using System.ComponentModel.DataAnnotations;

namespace VulnVerdict.Core.Data;

/// <summary>
/// A running total kept in the database so that /metrics, served by the web process, also reports what only the worker
/// did (mail sent, tickets that failed, feed failures). Label is empty for a counter without one.
/// </summary>
public class MetricCounter
{
    [MaxLength(64)] public string Name { get; set; } = "";
    [MaxLength(64)] public string Label { get; set; } = "";
    public long Value { get; set; }
    public DateTime UpdatedAt { get; set; }
}

/// <summary>
/// One row per day and tier, written by the worker: how many verdicts stood open, overdue, snoozed and under accepted
/// risk at the end of that day. The SLA trend charts read these; days before the table existed are filled in from the
/// verdict history as well as it allows and marked <see cref="Backfilled"/>.
/// </summary>
public class SlaSnapshot
{
    public long Id { get; set; }
    /// <summary>Local day in the Settings time zone.</summary>
    public DateOnly Day { get; set; }
    public VerdictTier Tier { get; set; }
    public int Open { get; set; }
    public int Overdue { get; set; }
    public int Snoozed { get; set; }
    public int AcceptedRisk { get; set; }
    /// <summary>Reconstructed from history rather than counted on the day.</summary>
    public bool Backfilled { get; set; }
    public DateTime RecordedAt { get; set; }
}
