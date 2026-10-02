using System.Diagnostics;
using System.Formats.Tar;
using System.Globalization;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Npgsql;
using VulnVerdict.Core.Data;

namespace VulnVerdict.Core.Services;

/// <summary>Backup settings. Stored under their own keys (not in AppSettings), so saving the Settings page cannot overwrite them.</summary>
public sealed class BackupOptions
{
    public bool Enabled { get; set; } = true;
    /// <summary>Local time (the Settings time zone), HH:mm.</summary>
    public string Time { get; set; } = "02:30";
    public int KeepDaily { get; set; } = 14;
    public int KeepWeekly { get; set; } = 8;
    /// <summary>True when an archive passphrase is saved. The passphrase itself never leaves the service.</summary>
    public bool Encrypt { get; set; }
}

/// <summary>One backup attempt, as recorded and shown.</summary>
public sealed record BackupResult(DateTime At, bool Ok, string Kind, string? File, long Bytes, double Seconds, string? Error, bool Encrypted);

/// <summary>manifest.json, the first entry of every archive.</summary>
public sealed class BackupManifest
{
    public int Format { get; set; } = 1;
    public DateTime CreatedUtc { get; set; }
    /// <summary>postgres | sqlite</summary>
    public string Provider { get; set; } = "";
    public string AppVersion { get; set; } = "";
    /// <summary>The last applied migration: restore into a console of the same or a newer version.</summary>
    public string? Migration { get; set; }
    /// <summary>database.dump (pg_dump custom format) or database.sqlite</summary>
    public string DatabaseFile { get; set; } = "";
    public long DatabaseBytes { get; set; }
    public string DatabaseSha256 { get; set; } = "";
    public int Keys { get; set; }
    public string Kind { get; set; } = "";
}

/// <summary>
/// The archive: a gzip-compressed tar holding manifest.json, keys/ (the data-protection key ring) and the database dump,
/// optionally wrapped in <see cref="BackupCrypto"/>. Plain archives open with tar; the restore script reads either.
/// </summary>
public static class BackupArchive
{
    public const string ManifestName = "manifest.json";
    public const string PostgresDump = "database.dump";
    public const string SqliteCopy = "database.sqlite";
    public const string KeysFolder = "keys/";
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { WriteIndented = true };

    public static async Task<string> FileSha256Async(string path, CancellationToken ct)
    {
        await using var s = File.OpenRead(path);
        return Convert.ToHexStringLower(await SHA256.HashDataAsync(s, ct));
    }

    /// <summary>Write the archive to <paramref name="path"/> (the caller passes a temporary name and renames it once verified).</summary>
    public static async Task WriteAsync(string path, BackupManifest manifest, string databasePath, string? keysDir, string? passphrase, CancellationToken ct, int iterations = BackupCrypto.DefaultIterations)
    {
        var keys = keysDir is not null && Directory.Exists(keysDir) ? Directory.GetFiles(keysDir).OrderBy(f => f, StringComparer.Ordinal).ToList() : new List<string>();
        manifest.Keys = keys.Count;
        manifest.DatabaseBytes = new FileInfo(databasePath).Length;
        manifest.DatabaseSha256 = await FileSha256Async(databasePath, ct);

        await using var file = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1 << 16);
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        var enc = string.IsNullOrEmpty(passphrase) ? null : new BackupCrypto.EncryptingStream(file, passphrase, iterations);
        try
        {
            // the Postgres dump is already compressed; the SQLite copy is not
            var level = manifest.Provider == "sqlite" ? CompressionLevel.Optimal : CompressionLevel.Fastest;
            await using (var gz = new GZipStream((Stream?)enc ?? file, level, leaveOpen: true))
            await using (var tar = new TarWriter(gz, TarEntryFormat.Pax, leaveOpen: true))
            {
                var entry = new PaxTarEntry(TarEntryType.RegularFile, ManifestName) { DataStream = new MemoryStream(JsonSerializer.SerializeToUtf8Bytes(manifest, Json)), ModificationTime = manifest.CreatedUtc };
                await tar.WriteEntryAsync(entry, ct);
                foreach (var k in keys) await tar.WriteEntryAsync(k, KeysFolder + Path.GetFileName(k), ct);
                await tar.WriteEntryAsync(databasePath, manifest.DatabaseFile, ct);
            }
            enc?.Complete();
            await file.FlushAsync(ct);
            file.Flush(flushToDisk: true);
        }
        finally { enc?.Dispose(); }
    }

    /// <summary>
    /// Read the archive end to end (decrypting when needed): the manifest must be present and the database entry must
    /// have the size and SHA-256 the manifest states. Throws with the reason when it does not.
    /// </summary>
    public static async Task<BackupManifest> VerifyAsync(string path, string? passphrase, CancellationToken ct)
    {
        await using var file = File.OpenRead(path);
        Stream source = file;
        if (BackupCrypto.IsEncrypted(file))
        {
            if (string.IsNullOrEmpty(passphrase)) throw new InvalidDataException("The backup is encrypted; a passphrase is needed to read it.");
            source = new BackupCrypto.DecryptingStream(file, passphrase);
        }
        BackupManifest? manifest = null;
        string? sha = null; long bytes = 0; var keys = 0;
        await using (source)
        await using (var gz = new GZipStream(source, CompressionMode.Decompress))
        await using (var tar = new TarReader(gz))
        {
            while (await tar.GetNextEntryAsync(false, ct) is { } entry)
            {
                if (entry.EntryType is not (TarEntryType.RegularFile or TarEntryType.V7RegularFile) || entry.DataStream is null) continue;
                if (entry.Name == ManifestName)
                    manifest = await JsonSerializer.DeserializeAsync<BackupManifest>(entry.DataStream, Json, ct);
                else if (entry.Name.StartsWith(KeysFolder, StringComparison.Ordinal)) keys++;
                else if (entry.Name is PostgresDump or SqliteCopy)
                {
                    using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                    var buf = new byte[1 << 16];
                    int n;
                    while ((n = await entry.DataStream.ReadAsync(buf, ct)) > 0) { hash.AppendData(buf, 0, n); bytes += n; }
                    sha = Convert.ToHexStringLower(hash.GetHashAndReset());
                }
            }
        }
        if (manifest is null) throw new InvalidDataException("The archive has no manifest.json; it is not a VulnVerdict backup.");
        if (sha is null) throw new InvalidDataException("The archive has no database in it.");
        if (bytes != manifest.DatabaseBytes || !sha.Equals(manifest.DatabaseSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("The database in the archive does not match its manifest (damaged or incomplete).");
        if (keys != manifest.Keys) throw new InvalidDataException("The archive holds " + keys + " key file(s), its manifest says " + manifest.Keys + ".");
        return manifest;
    }
}

/// <summary>A backup file's name carries when it was taken and why: vulnverdict-20261002-013000Z-scheduled.vvbak(.enc).</summary>
public sealed partial record BackupFile(string Name, DateTime TakenUtc, string Kind, bool Encrypted)
{
    public const string Extension = ".vvbak";
    public const string EncryptedExtension = ".vvbak.enc";

    public static string NameFor(DateTime utc, string kind, bool encrypted) =>
        "vulnverdict-" + utc.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture) + "Z-" + kind + (encrypted ? EncryptedExtension : Extension);

    public static BackupFile? Parse(string name)
    {
        var m = NameRx().Match(name);
        if (!m.Success || !DateTime.TryParseExact(m.Groups[1].Value, "yyyyMMdd-HHmmss", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var at)) return null;
        return new BackupFile(name, at, m.Groups[2].Value, m.Groups[3].Success);
    }

    [GeneratedRegex(@"^vulnverdict-(\d{8}-\d{6})Z-([a-z-]+)\.vvbak(\.enc)?$")]
    private static partial Regex NameRx();
}

/// <summary>
/// Which backups to keep: the newest backup of each of the last <c>daily</c> days that have one, and the newest of each
/// of the last <c>weekly</c> ISO weeks that have one. Days and weeks without a backup do not count, so a run of failed
/// nights never ages the last good backups out. Days are local days in the Settings time zone.
/// </summary>
public static class BackupRetention
{
    public static (List<BackupFile> Keep, List<BackupFile> Delete) Select(IEnumerable<BackupFile> files, int daily, int weekly, TimeZoneInfo tz)
    {
        var all = files.OrderByDescending(f => f.TakenUtc).ToList();
        DateTime Local(BackupFile f) => TimeZoneInfo.ConvertTimeFromUtc(DateTime.SpecifyKind(f.TakenUtc, DateTimeKind.Utc), tz);
        var keep = new HashSet<BackupFile>();
        foreach (var day in all.GroupBy(f => Local(f).Date).OrderByDescending(g => g.Key).Take(Math.Max(daily, 1)))
            keep.Add(day.First());
        foreach (var week in all.GroupBy(f => (ISOWeek.GetYear(Local(f)), ISOWeek.GetWeekOfYear(Local(f)))).OrderByDescending(g => g.Key).Take(Math.Max(weekly, 0)))
            keep.Add(week.First());
        return (all.Where(keep.Contains).ToList(), all.Where(f => !keep.Contains(f)).ToList());
    }
}

public static class BackupSchedule
{
    /// <summary>How long a failed scheduled backup waits before the next try.</summary>
    public static readonly TimeSpan RetryAfter = TimeSpan.FromHours(1);

    /// <summary>The most recent scheduled time at or before now, in UTC. A time the clocks skip (spring forward) runs an hour later.</summary>
    public static DateTime LastSlotUtc(DateTime nowUtc, TimeZoneInfo tz, TimeOnly at)
    {
        var localNow = TimeZoneInfo.ConvertTimeFromUtc(DateTime.SpecifyKind(nowUtc, DateTimeKind.Utc), tz);
        DateTime Slot(DateTime day)
        {
            var local = DateTime.SpecifyKind(day.Date + at.ToTimeSpan(), DateTimeKind.Unspecified);
            if (tz.IsInvalidTime(local)) local = local.AddHours(1);
            return TimeZoneInfo.ConvertTimeToUtc(local, tz);
        }
        var today = Slot(localNow);
        return today <= nowUtc ? today : Slot(localNow.AddDays(-1));
    }

    /// <summary>Due when no good backup has been taken since the last scheduled time, and the last attempt (if it failed) was at least an hour ago.</summary>
    public static bool IsDue(DateTime nowUtc, TimeZoneInfo tz, string time, DateTime? lastOkUtc, DateTime? lastAttemptUtc)
    {
        if (!TimeOnly.TryParse(time, CultureInfo.InvariantCulture, out var at)) at = new TimeOnly(2, 30);
        var slot = LastSlotUtc(nowUtc, tz, at);
        if (lastOkUtc is not null && lastOkUtc >= slot) return false;
        return lastAttemptUtc is null || lastAttemptUtc < slot || nowUtc - lastAttemptUtc >= RetryAfter;
    }
}

public enum BackupHealthState { Disabled, Waiting, Ok, Failed, Stale }

/// <summary>What the Sources page, the digest footer and the administrator alert say about backups.</summary>
public sealed record BackupHealth(BackupHealthState State, BackupResult? Last, BackupResult? LastOk, string Text)
{
    /// <summary>A backup older than this is no backup: the digest says so and the administrator is emailed.</summary>
    public static readonly TimeSpan StaleAfter = TimeSpan.FromHours(48);

    /// <summary>True when the administrator should be told: the last attempt failed, or there is no good backup from the last 48 hours.</summary>
    public bool Alarm => State is BackupHealthState.Failed or BackupHealthState.Stale;
    /// <summary>The digest footer line, only when the last good backup is older than 48 hours (or there has never been one).</summary>
    public string? DigestWarning { get; init; }

    public static BackupHealth Evaluate(bool enabled, BackupResult? last, BackupResult? lastOk, DateTime? firstCheckUtc, DateTime nowUtc)
    {
        static string Ago(DateTime at, DateTime now)
        {
            var d = now - at;
            return d.TotalMinutes < 90 ? Math.Max((int)d.TotalMinutes, 1) + " min ago" : d.TotalHours < 48 ? (int)d.TotalHours + " h ago" : (int)d.TotalDays + " days ago";
        }
        static string Size(long bytes) => bytes >= 1 << 20 ? (bytes / 1048576.0).ToString("0.#", CultureInfo.InvariantCulture) + " MB" : Math.Max(bytes / 1024, 1) + " KB";

        var good = lastOk is null ? "No good backup has ever been taken." : "The last good backup was " + Ago(lastOk.At, nowUtc) + " (" + lastOk.At.ToString("d MMM HH:mm", CultureInfo.InvariantCulture) + " UTC).";
        var fresh = lastOk is not null && nowUtc - lastOk.At <= StaleAfter;
        var failed = last is { Ok: false } && (lastOk is null || last.At > lastOk.At);
        if (!enabled && !failed)
            return new BackupHealth(BackupHealthState.Disabled, last, lastOk, "Scheduled backups are off. " + (lastOk is null ? "" : good));
        if (failed)
        {
            var text = "The backup " + Ago(last!.At, nowUtc) + " failed: " + (last.Error ?? "unknown error").TrimEnd().TrimEnd('.') + ". " + good;
            return new BackupHealth(BackupHealthState.Failed, last, lastOk, text) { DigestWarning = fresh ? null : "Database backup is failing. " + good };
        }
        if (fresh)
            return new BackupHealth(BackupHealthState.Ok, last, lastOk, "Last backup " + Ago(lastOk!.At, nowUtc) + ": " + Size(lastOk.Bytes) + " in " + lastOk.Seconds.ToString("0.#", CultureInfo.InvariantCulture) + " s" + (lastOk.Encrypted ? ", encrypted" : "") + ".");
        // a new install has until its first two nights have passed
        if (lastOk is null && (firstCheckUtc is null || nowUtc - firstCheckUtc <= StaleAfter))
            return new BackupHealth(BackupHealthState.Waiting, last, lastOk, "No backup yet; the first runs at the scheduled time.");
        return new BackupHealth(BackupHealthState.Stale, last, lastOk, "Backups are not running. " + good) { DigestWarning = "Database backup is overdue. " + good };
    }
}

/// <summary>
/// Scheduled and on-demand backups of the database and the data-protection keys into the backups folder under the data
/// directory. Postgres is dumped with pg_dump (custom format) and checked with pg_restore --list; SQLite is copied with
/// VACUUM INTO and checked with PRAGMA integrity_check. The archive is written under a temporary name, read back and
/// compared with its manifest, and only then renamed into place, so a file with a backup's name is always a whole backup.
/// </summary>
public sealed class BackupService
{
    public const string EnabledKey = "backup:enabled";
    public const string TimeKey = "backup:time";
    public const string KeepDailyKey = "backup:keepDaily";
    public const string KeepWeeklyKey = "backup:keepWeekly";
    public const string PassphraseKey = "backup:passphrase";
    public const string HistoryKey = "state:backup:history";
    public const string LastOkKey = "state:backup:lastOk";
    public const string FirstCheckKey = "state:backup:firstCheck";
    public const string FolderName = "backups";
    private const int HistoryLength = 30;
    private static readonly TimeSpan LockStaleAfter = TimeSpan.FromHours(6);

    private readonly IDbContextFactory<VvDbContext> _factory;
    private readonly SettingsService _settings;
    private readonly IDataProtector _protector;
    private readonly WorkerOptions _opt;
    private readonly ILogger<BackupService> _log;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public BackupService(IDbContextFactory<VvDbContext> factory, SettingsService settings, IDataProtectionProvider dp, WorkerOptions opt, ILogger<BackupService> log)
    {
        _factory = factory; _settings = settings; _opt = opt; _log = log;
        _protector = dp.CreateProtector("VulnVerdict.Secrets.v1");
    }

    public string BackupDir => Path.Combine(_opt.DataDir, FolderName);
    public string KeysDir => Path.Combine(_opt.DataDir, "keys");
    public bool Busy => _gate.CurrentCount == 0;

    /// <summary>Runs pg_dump and pg_restore. Replaced in tests, where neither is installed.</summary>
    public Func<string, IReadOnlyList<string>, IReadOnlyDictionary<string, string>, CancellationToken, Task<(int ExitCode, string Output)>> RunProcess { get; set; } = RunProcessAsync;
    /// <summary>PBKDF2 work factor for encrypted archives. Tests lower it.</summary>
    public int KdfIterations { get; set; } = BackupCrypto.DefaultIterations;

    // ------------------------------------------------------------------ settings

    public async Task<BackupOptions> LoadOptionsAsync(CancellationToken ct = default)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        var rows = await db.Settings.AsNoTracking().Where(s => s.Key.StartsWith("backup:")).ToDictionaryAsync(s => s.Key, s => s.Value, ct);
        var o = new BackupOptions();
        if (rows.TryGetValue(EnabledKey, out var e) && bool.TryParse(e, out var enabled)) o.Enabled = enabled;
        if (rows.TryGetValue(TimeKey, out var t) && TimeOnly.TryParse(t, CultureInfo.InvariantCulture, out _)) o.Time = t!;
        if (rows.TryGetValue(KeepDailyKey, out var d) && int.TryParse(d, out var daily)) o.KeepDaily = daily;
        if (rows.TryGetValue(KeepWeeklyKey, out var w) && int.TryParse(w, out var weekly)) o.KeepWeekly = weekly;
        o.Encrypt = !string.IsNullOrEmpty(rows.GetValueOrDefault(PassphraseKey));
        return o;
    }

    public async Task SaveOptionsAsync(BackupOptions o, string actor, CancellationToken ct = default)
    {
        if (!TimeOnly.TryParse(o.Time, CultureInfo.InvariantCulture, out var at)) throw new ArgumentException("The backup time must look like 02:30.");
        if (o.KeepDaily is < 1 or > 365) throw new ArgumentException("Keep between 1 and 365 daily backups.");
        if (o.KeepWeekly is < 0 or > 520) throw new ArgumentException("Keep between 0 and 520 weekly backups.");
        await using var db = await _factory.CreateDbContextAsync(ct);
        var now = DateTime.UtcNow;
        Upsert(db, EnabledKey, o.Enabled.ToString(), false, now);
        Upsert(db, TimeKey, at.ToString("HH:mm", CultureInfo.InvariantCulture), false, now);
        Upsert(db, KeepDailyKey, o.KeepDaily.ToString(CultureInfo.InvariantCulture), false, now);
        Upsert(db, KeepWeeklyKey, o.KeepWeekly.ToString(CultureInfo.InvariantCulture), false, now);
        db.Audit.Add(new AuditEntry { At = now, Actor = actor, Action = "backup.settings", Target = "backup", After = (o.Enabled ? "nightly at " + at.ToString("HH:mm", CultureInfo.InvariantCulture) : "off") + ", keep " + o.KeepDaily + " daily and " + o.KeepWeekly + " weekly" });
        await db.SaveChangesAsync(ct);
    }

    /// <summary>Set (or with null or empty, remove) the archive passphrase. Stored encrypted like every other secret; never read back by the console's pages.</summary>
    public async Task SetPassphraseAsync(string? passphrase, string actor, CancellationToken ct = default)
    {
        if (!string.IsNullOrEmpty(passphrase) && passphrase.Length < 12) throw new ArgumentException("Use a passphrase of at least 12 characters.");
        await using var db = await _factory.CreateDbContextAsync(ct);
        var now = DateTime.UtcNow;
        Upsert(db, PassphraseKey, string.IsNullOrEmpty(passphrase) ? null : _protector.Protect(passphrase), true, now);
        db.Audit.Add(new AuditEntry { At = now, Actor = actor, Action = "backup.passphrase", Target = "backup", After = string.IsNullOrEmpty(passphrase) ? "removed: new backups are not encrypted" : "set: new backups are encrypted" });
        await db.SaveChangesAsync(ct);
    }

    private async Task<string?> PassphraseAsync(CancellationToken ct)
    {
        var stored = await _settings.GetStateAsync(PassphraseKey, ct);
        if (string.IsNullOrEmpty(stored)) return null;
        // unreadable (the key ring was replaced): fail the backup rather than quietly write an unencrypted one
        try { return _protector.Unprotect(stored); }
        catch (Exception ex) { throw new InvalidOperationException("The saved backup passphrase cannot be read (the data-protection keys changed). Set it again under Settings.", ex); }
    }

    private static void Upsert(VvDbContext db, string key, string? value, bool encrypted, DateTime now)
    {
        var row = db.Settings.FirstOrDefault(s => s.Key == key);
        if (row is null) db.Settings.Add(new AppSetting { Key = key, Value = value, Encrypted = encrypted, UpdatedAt = now });
        else { row.Value = value; row.Encrypted = encrypted; row.UpdatedAt = now; }
    }

    // ------------------------------------------------------------------ state and health

    public async Task<List<BackupResult>> HistoryAsync(CancellationToken ct = default) => Read<List<BackupResult>>(await _settings.GetStateAsync(HistoryKey, ct)) ?? new();

    public async Task<BackupHealth> HealthAsync(CancellationToken ct = default) => await HealthAsync(_settings, (await LoadOptionsAsync(ct)).Enabled, DateTime.UtcNow, ct);

    /// <summary>Health from the recorded state alone, for callers that only hold the settings service (the digest).</summary>
    public static async Task<BackupHealth> HealthAsync(SettingsService settings, bool? enabled, DateTime nowUtc, CancellationToken ct = default)
    {
        enabled ??= !bool.TryParse(await settings.GetStateAsync(EnabledKey, ct), out var e) || e;
        var history = Read<List<BackupResult>>(await settings.GetStateAsync(HistoryKey, ct));
        var lastOk = Read<BackupResult>(await settings.GetStateAsync(LastOkKey, ct));
        var first = DateTime.TryParse(await settings.GetStateAsync(FirstCheckKey, ct), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var f) ? f.ToUniversalTime() : (DateTime?)null;
        return BackupHealth.Evaluate(enabled.Value, history?.FirstOrDefault(), lastOk, first, nowUtc);
    }

    private static T? Read<T>(string? json) where T : class
    {
        if (string.IsNullOrEmpty(json)) return null;
        try { return JsonSerializer.Deserialize<T>(json); } catch (JsonException) { return null; }
    }

    private async Task RecordAsync(BackupResult r, CancellationToken ct)
    {
        var history = await HistoryAsync(ct);
        history.Insert(0, r);
        await _settings.SetStateAsync(HistoryKey, JsonSerializer.Serialize(history.Take(HistoryLength)), ct);
        if (r.Ok) await _settings.SetStateAsync(LastOkKey, JsonSerializer.Serialize(r), ct);
    }

    /// <summary>The backups in the folder, newest first.</summary>
    public List<(BackupFile File, long Bytes)> List()
    {
        if (!Directory.Exists(BackupDir)) return new();
        return Directory.GetFiles(BackupDir).Select(p => (File: BackupFile.Parse(Path.GetFileName(p)), Bytes: new FileInfo(p).Length))
            .Where(x => x.File is not null).Select(x => (x.File!, x.Bytes)).OrderByDescending(x => x.Item1.TakenUtc).ToList();
    }

    // ------------------------------------------------------------------ worker

    /// <summary>The worker's step: take the nightly backup when it is due, then email the administrator if backups are failing or stale.</summary>
    public static async Task RunIfDueAsync(IServiceProvider sp, CancellationToken ct)
    {
        var backups = sp.GetRequiredService<BackupService>();
        var settings = sp.GetRequiredService<SettingsService>();
        var now = DateTime.UtcNow;
        var first = DateTime.TryParse(await settings.GetStateAsync(FirstCheckKey, ct), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var f) ? f.ToUniversalTime() : (DateTime?)null;
        if (first is null) await settings.SetStateAsync(FirstCheckKey, (first = now).Value.ToString("O"), ct);
        var o = await backups.LoadOptionsAsync(ct);
        if (o.Enabled)
        {
            var history = await backups.HistoryAsync(ct);
            var lastOk = Read<BackupResult>(await settings.GetStateAsync(LastOkKey, ct));
            var tz = (await settings.LoadAsync(ct)).ResolveTimeZone();
            // a console that has never been backed up waits for its first scheduled time rather than running at start-up
            if (BackupSchedule.IsDue(now, tz, o.Time, lastOk?.At ?? first, history.FirstOrDefault()?.At))
                await backups.RunAsync("scheduled", "system", ct);
        }
        var health = await backups.HealthAsync(ct);
        if (health.Alarm)
            await WorkerService.AdminAlertAsync(sp, health.State == BackupHealthState.Failed ? "Database backup failed" : "Database backups are not running",
                health.Text + "\nBackups are written to the backups folder in the data volume. See Settings, Backups, and docs/backup.md.", ct);
    }

    // ------------------------------------------------------------------ run

    /// <summary>Take a backup now. Never throws for a failed backup: the result says what went wrong, and is recorded.</summary>
    public async Task<BackupResult> RunAsync(string kind, string actor, CancellationToken ct = default)
    {
        var started = DateTime.UtcNow;
        if (!await _gate.WaitAsync(0, ct)) return new BackupResult(started, false, kind, null, 0, 0, "A backup is already running.", false);
        var sw = Stopwatch.StartNew();
        var work = Path.Combine(_opt.DataDir, "backup-work", Guid.NewGuid().ToString("N"));
        string? lockPath = null, tmp = null;
        BackupResult result;
        try
        {
            Directory.CreateDirectory(BackupDir);
            lockPath = TakeLock();
            if (lockPath is null) return new BackupResult(started, false, kind, null, 0, 0, "A backup is already running.", false);
            Directory.CreateDirectory(work);
            var passphrase = await PassphraseAsync(ct);
            var manifest = new BackupManifest { CreatedUtc = started, Kind = kind, AppVersion = Environment.GetEnvironmentVariable("VV_VERSION") ?? "dev" };
            string dump;
            await using (var db = await _factory.CreateDbContextAsync(ct))
            {
                try { manifest.Migration = (await db.Database.GetAppliedMigrationsAsync(ct)).LastOrDefault(); } catch { }
                var connectionString = db.Database.GetConnectionString() ?? throw new InvalidOperationException("The database connection string is not available.");
                if (db.Database.IsNpgsql())
                {
                    manifest.Provider = "postgres"; manifest.DatabaseFile = BackupArchive.PostgresDump;
                    dump = Path.Combine(work, BackupArchive.PostgresDump);
                    await DumpPostgresAsync(connectionString, dump, ct);
                }
                else
                {
                    manifest.Provider = "sqlite"; manifest.DatabaseFile = BackupArchive.SqliteCopy;
                    dump = Path.Combine(work, BackupArchive.SqliteCopy);
                    await CopySqliteAsync(connectionString, dump, ct);
                }
            }
            var name = BackupFile.NameFor(started, kind, passphrase is not null);
            var final = Path.Combine(BackupDir, name);
            tmp = final + ".tmp";
            if (File.Exists(tmp)) File.Delete(tmp);
            await BackupArchive.WriteAsync(tmp, manifest, dump, KeysDir, passphrase, ct, KdfIterations);
            await BackupArchive.VerifyAsync(tmp, passphrase, ct);
            File.Move(tmp, final);   // same folder, so the rename is atomic: the name never refers to half a backup
            tmp = null;
            result = new BackupResult(started, true, kind, name, new FileInfo(final).Length, sw.Elapsed.TotalSeconds, null, passphrase is not null);
            _log.LogInformation("Backup {File} written: {Bytes} bytes in {Seconds:0.0} s", name, result.Bytes, result.Seconds);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            _log.LogError(ex, "Backup failed");
            var msg = ex.Message.Length > 500 ? ex.Message[..500] : ex.Message;
            result = new BackupResult(started, false, kind, null, 0, sw.Elapsed.TotalSeconds, msg, false);
        }
        finally
        {
            try { if (tmp is not null) File.Delete(tmp); } catch { }
            try { if (Directory.Exists(work)) Directory.Delete(work, true); } catch { }
            try { if (lockPath is not null) File.Delete(lockPath); } catch { }
            _gate.Release();
        }
        await RecordAsync(result, ct);
        await AuditAsync(actor, result, ct);
        // only a good backup prunes: failures never cost an older backup
        if (result.Ok) await PruneAsync(ct);
        return result;
    }

    /// <summary>One backup at a time across the web and worker processes, which share the folder. A lock left by a killed process expires.</summary>
    private string? TakeLock()
    {
        var path = Path.Combine(BackupDir, ".lock");
        try
        {
            if (File.Exists(path) && DateTime.UtcNow - File.GetLastWriteTimeUtc(path) > LockStaleAfter) File.Delete(path);
            using var fs = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            return path;
        }
        catch (IOException) { return null; }
    }

    /// <summary>pg_dump in custom format, then pg_restore --list to prove the dump reads back. Public for tests.</summary>
    public async Task DumpPostgresAsync(string connectionString, string dump, CancellationToken ct = default)
    {
        var c = new NpgsqlConnectionStringBuilder(connectionString);
        var args = new List<string> { "--format=custom", "--no-password", "--dbname=" + c.Database, "--file=" + dump };
        if (!string.IsNullOrEmpty(c.Host)) args.Add("--host=" + c.Host);   // a directory here means the Unix socket (the all-in-one image)
        if (c.Port > 0) args.Add("--port=" + c.Port.ToString(CultureInfo.InvariantCulture));
        if (!string.IsNullOrEmpty(c.Username)) args.Add("--username=" + c.Username);
        // the password goes in the environment of the child process only, never on a command line
        var env = new Dictionary<string, string> { ["PGCONNECT_TIMEOUT"] = "15" };
        if (!string.IsNullOrEmpty(c.Password)) env["PGPASSWORD"] = c.Password;

        var (code, output) = await RunProcess("pg_dump", args, env, ct);
        if (code != 0 || !File.Exists(dump)) throw new InvalidOperationException("pg_dump failed (exit " + code + "): " + Tail(output));
        var (listCode, listing) = await RunProcess("pg_restore", new[] { "--list", dump }, new Dictionary<string, string>(), ct);
        if (listCode != 0) throw new InvalidOperationException("The dump did not verify (pg_restore --list, exit " + listCode + "): " + Tail(listing));
        if (!listing.Contains("TABLE DATA", StringComparison.Ordinal)) throw new InvalidOperationException("The dump did not verify: it holds no table data.");
    }

    private static async Task CopySqliteAsync(string connectionString, string copy, CancellationToken ct)
    {
        // VACUUM INTO takes a consistent copy of a live database (WAL included) without blocking writers for long
        await using (var conn = new SqliteConnection(connectionString))
        {
            await conn.OpenAsync(ct);
            await using var cmd = conn.CreateCommand();
            cmd.CommandText = "VACUUM INTO $path";
            cmd.Parameters.AddWithValue("$path", copy);
            cmd.CommandTimeout = 1800;
            await cmd.ExecuteNonQueryAsync(ct);
        }
        await using var check = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = copy, Mode = SqliteOpenMode.ReadOnly, Pooling = false }.ToString());
        await check.OpenAsync(ct);
        await using var pragma = check.CreateCommand();
        pragma.CommandText = "PRAGMA integrity_check";
        var verdict = (await pragma.ExecuteScalarAsync(ct))?.ToString();
        if (!string.Equals(verdict, "ok", StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("The SQLite copy did not verify (integrity_check: " + verdict + ").");
    }

    private static string Tail(string s) => (s = s.Trim()).Length > 400 ? s[^400..] : s;

    private static async Task<(int ExitCode, string Output)> RunProcessAsync(string file, IReadOnlyList<string> args, IReadOnlyDictionary<string, string> env, CancellationToken ct)
    {
        var psi = new ProcessStartInfo(file) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        foreach (var a in args) psi.ArgumentList.Add(a);
        foreach (var (k, v) in env) psi.Environment[k] = v;
        Process p;
        try { p = Process.Start(psi) ?? throw new InvalidOperationException(file + " did not start."); }
        catch (System.ComponentModel.Win32Exception)
        {
            throw new InvalidOperationException(file + " is not installed. The console image carries the PostgreSQL client from this release on; on your own host install postgresql-client for the server's major version.");
        }
        using (p)
        {
            var stdout = p.StandardOutput.ReadToEndAsync(ct);
            var stderr = p.StandardError.ReadToEndAsync(ct);
            try { await p.WaitForExitAsync(ct); }
            catch (OperationCanceledException) { try { p.Kill(true); } catch { } throw; }
            var o = await stdout; var e = await stderr;
            return (p.ExitCode, e.Length > 0 ? o + "\n" + e : o);
        }
    }

    private async Task PruneAsync(CancellationToken ct)
    {
        try
        {
            var o = await LoadOptionsAsync(ct);
            var tz = (await _settings.LoadAsync(ct)).ResolveTimeZone();
            var (_, delete) = BackupRetention.Select(List().Select(x => x.File), o.KeepDaily, o.KeepWeekly, tz);
            foreach (var f in delete)
            {
                File.Delete(Path.Combine(BackupDir, f.Name));
                _log.LogInformation("Backup {File} removed by retention", f.Name);
            }
            // a temporary file left by a process that was killed mid-backup
            foreach (var t in Directory.GetFiles(BackupDir, "*.tmp").Where(t => DateTime.UtcNow - File.GetLastWriteTimeUtc(t) > LockStaleAfter)) File.Delete(t);
        }
        catch (Exception ex) { _log.LogWarning(ex, "Backup retention could not run"); }
    }

    private async Task AuditAsync(string actor, BackupResult r, CancellationToken ct)
    {
        try
        {
            await using var db = await _factory.CreateDbContextAsync(ct);
            db.Audit.Add(new AuditEntry { At = DateTime.UtcNow, Actor = actor, Action = r.Ok ? "backup.run" : "backup.failed", Target = r.File ?? r.Kind, After = r.Ok ? r.Bytes + " bytes" + (r.Encrypted ? ", encrypted" : "") : r.Error });
            await db.SaveChangesAsync(ct);
        }
        catch (Exception ex) { _log.LogWarning(ex, "Audit entry could not be written"); }
    }
}
