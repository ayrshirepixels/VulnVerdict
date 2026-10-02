using System.ComponentModel.DataAnnotations;

namespace VulnVerdict.Core.Data;

/// <summary>
/// One notification waiting to leave the box: a signed webhook, or a Teams or Slack message. Written in the same save
/// as the change it reports, so it survives a restart and can be queued by the web process and sent by the worker.
/// </summary>
public class OutboxMessage
{
    public long Id { get; set; }
    /// <summary>webhook, teams or slack</summary>
    [MaxLength(16)] public string Kind { get; set; } = "";
    [MaxLength(64)] public string Event { get; set; } = "";
    public Guid? VerdictId { get; set; }
    /// <summary>A webhook: the exact body to post. Teams and Slack: what the message is about; the card is built when it is sent.</summary>
    public string PayloadJson { get; set; } = "{}";
    public DateTime CreatedAt { get; set; }
    /// <summary>Attempts started, counting the one in progress.</summary>
    public int Attempts { get; set; }
    public DateTime NextAttemptAt { get; set; }
    [MaxLength(500)] public string? LastError { get; set; }
    public DateTime? DeliveredAt { get; set; }
    /// <summary>Set when the attempts ran out. The row stays for the health notice and is not sent again.</summary>
    public DateTime? FailedAt { get; set; }
}
