using System.Formats.Tar;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging.Abstractions;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Digest;
using VulnVerdict.Core.Services;

namespace VulnVerdict.Tests;

/// <summary>Backups: which to keep, when one is due, what counts as healthy, and the archive itself (written whole or not at all, verified, optionally encrypted).</summary>
public class BackupTests : IDisposable
{
    private readonly OpsTestHost _host = new();
    private static readonly TimeZoneInfo London = TimeZoneInfo.FindSystemTimeZoneById("Europe/London");

    public void Dispose() => _host.Dispose();

    private BackupService Service()
    {
        Directory.CreateDirectory(Path.Combine(_host.DataDir, "keys"));
        File.WriteAllText(Path.Combine(_host.DataDir, "keys", "key-1.xml"), "<key id=\"1\"/>");
        File.WriteAllText(Path.Combine(_host.DataDir, "keys", "key-2.xml"), "<key id=\"2\"/>");
        return new BackupService(_host.Db, _host.Settings, _host.Protection, new WorkerOptions { DataDir = _host.DataDir }, NullLogger<BackupService>.Instance) { KdfIterations = 1000 };
    }

    // ---- retention

    private static BackupFile At(string utc, string kind = "scheduled") =>
        BackupFile.Parse(BackupFile.NameFor(DateTime.Parse(utc, null, System.Globalization.DateTimeStyles.AdjustToUniversal | System.Globalization.DateTimeStyles.AssumeUniversal), kind, false))!;

    [Fact]
    public void A_backup_name_round_trips_and_other_files_are_ignored()
    {
        var f = BackupFile.Parse("vulnverdict-20261002-013000Z-scheduled.vvbak.enc");
        Assert.NotNull(f);
        Assert.Equal(new DateTime(2026, 10, 2, 1, 30, 0, DateTimeKind.Utc), f!.TakenUtc);
        Assert.Equal("scheduled", f.Kind);
        Assert.True(f.Encrypted);
        Assert.Equal(f.Name, BackupFile.NameFor(f.TakenUtc, f.Kind, true));
        Assert.Null(BackupFile.Parse("vulnverdict-20261002-013000Z-scheduled.vvbak.tmp"));
        Assert.Null(BackupFile.Parse("notes.txt"));
        Assert.Null(BackupFile.Parse("../vulnverdict-20261002-013000Z-scheduled.vvbak"));
    }

    [Fact]
    public void Retention_keeps_fourteen_daily_and_eight_weekly()
    {
        // one backup a night for 100 nights, ending Friday 2 October 2026
        var files = Enumerable.Range(0, 100).Select(i => At(new DateTime(2026, 10, 2, 1, 30, 0, DateTimeKind.Utc).AddDays(-i).ToString("u"))).ToList();
        var (keep, delete) = BackupRetention.Select(files, 14, 8, London);

        Assert.Equal(100, keep.Count + delete.Count);
        // the last 14 days, plus the newest backup (Sunday) of each of the 8 most recent ISO weeks; the three most recent
        // weeks' newest backups are already among the 14 daily ones
        var daily = files.Take(14).ToList();
        Assert.All(daily, f => Assert.Contains(f, keep));
        Assert.Equal(14 + 5, keep.Count);
        var weekly = keep.Except(daily).ToList();
        Assert.All(weekly, f => Assert.Equal(DayOfWeek.Sunday, TimeZoneInfo.ConvertTimeFromUtc(f.TakenUtc, London).DayOfWeek));
        Assert.Equal(new DateTime(2026, 8, 16, 1, 30, 0, DateTimeKind.Utc), keep.Min(f => f.TakenUtc));
    }

    [Fact]
    public void Retention_keeps_only_the_newest_backup_of_a_day_and_counts_days_that_have_one()
    {
        var files = new List<BackupFile>
        {
            At("2026-10-02 01:30:00Z"), At("2026-10-02 09:00:00Z", "manual"), At("2026-10-02 15:00:00Z", "manual"),
            // then nothing for a month: the old backups are the only ones, and must not age out
            At("2026-09-01 01:30:00Z"), At("2026-08-31 01:30:00Z"), At("2026-08-30 01:30:00Z"),
        };
        var (keep, delete) = BackupRetention.Select(files, 3, 0, London);
        Assert.Equal(new[] { "2026-10-02 15:00", "2026-09-01 01:30", "2026-08-31 01:30" }, keep.Select(f => f.TakenUtc.ToString("yyyy-MM-dd HH:mm")));
        Assert.Equal(3, delete.Count);
    }

    [Fact]
    public void Retention_days_are_local_days()
    {
        // 23:30 UTC on 1 July is 00:30 on 2 July in London: the same local day as the 2 July 20:00 UTC backup
        var files = new List<BackupFile> { At("2026-07-01 23:30:00Z"), At("2026-07-02 20:00:00Z"), At("2026-07-01 12:00:00Z") };
        var (keep, _) = BackupRetention.Select(files, 14, 0, London);
        Assert.Equal(new[] { "2026-07-02 20:00", "2026-07-01 12:00" }, keep.Select(f => f.TakenUtc.ToString("yyyy-MM-dd HH:mm")));
    }

    [Fact]
    public void Retention_never_deletes_everything()
    {
        var (keep, delete) = BackupRetention.Select(new[] { At("2026-10-02 01:30:00Z") }, 0, 0, London);
        Assert.Single(keep);
        Assert.Empty(delete);
    }

    // ---- schedule

    [Fact]
    public void A_backup_is_due_after_the_scheduled_time_once_a_day()
    {
        static DateTime Utc(string s) => DateTime.Parse(s, null, System.Globalization.DateTimeStyles.AdjustToUniversal | System.Globalization.DateTimeStyles.AssumeUniversal);
        // British Summer Time: 02:30 local is 01:30 UTC
        Assert.False(BackupSchedule.IsDue(Utc("2026-07-10 01:29:00Z"), London, "02:30", Utc("2026-07-09 01:31:00Z"), Utc("2026-07-09 01:31:00Z")));
        Assert.True(BackupSchedule.IsDue(Utc("2026-07-10 01:30:00Z"), London, "02:30", Utc("2026-07-09 01:31:00Z"), Utc("2026-07-09 01:31:00Z")));
        Assert.False(BackupSchedule.IsDue(Utc("2026-07-10 08:00:00Z"), London, "02:30", Utc("2026-07-10 01:31:00Z"), Utc("2026-07-10 01:31:00Z")));
        // never backed up: due at once
        Assert.True(BackupSchedule.IsDue(Utc("2026-07-10 08:00:00Z"), London, "02:30", null, null));
        // a manual backup the evening before does not replace the nightly one
        Assert.True(BackupSchedule.IsDue(Utc("2026-07-10 01:40:00Z"), London, "02:30", Utc("2026-07-09 21:00:00Z"), Utc("2026-07-09 21:00:00Z")));
        // failed at 01:31: not again for an hour, then again
        Assert.False(BackupSchedule.IsDue(Utc("2026-07-10 02:00:00Z"), London, "02:30", Utc("2026-07-09 01:31:00Z"), Utc("2026-07-10 01:31:00Z")));
        Assert.True(BackupSchedule.IsDue(Utc("2026-07-10 02:31:00Z"), London, "02:30", Utc("2026-07-09 01:31:00Z"), Utc("2026-07-10 01:31:00Z")));
    }

    [Fact]
    public void The_night_the_clocks_change_still_has_one_backup()
    {
        // 29 March 2026: 01:00 to 02:00 local does not exist in London, so 01:30 runs at 02:30 local (01:30 UTC)
        var slot = BackupSchedule.LastSlotUtc(new DateTime(2026, 3, 29, 12, 0, 0, DateTimeKind.Utc), London, new TimeOnly(1, 30));
        Assert.Equal(new DateTime(2026, 3, 29, 1, 30, 0, DateTimeKind.Utc), slot);
        // 25 October 2026: 01:30 local happens twice; either instant is on the right night
        var autumn = BackupSchedule.LastSlotUtc(new DateTime(2026, 10, 25, 12, 0, 0, DateTimeKind.Utc), London, new TimeOnly(1, 30));
        Assert.InRange(autumn, new DateTime(2026, 10, 25, 0, 30, 0, DateTimeKind.Utc), new DateTime(2026, 10, 25, 1, 30, 0, DateTimeKind.Utc));
    }

    // ---- health

    private static readonly DateTime Now = new(2026, 10, 2, 9, 0, 0, DateTimeKind.Utc);
    private static BackupResult Good(double hoursAgo) => new(Now.AddHours(-hoursAgo), true, "scheduled", "vulnverdict-x.vvbak", 5 << 20, 12.5, null, false);
    private static BackupResult Bad(double hoursAgo) => new(Now.AddHours(-hoursAgo), false, "scheduled", null, 0, 1, "pg_dump failed (exit 1): connection refused.", false);

    [Fact]
    public void Health_is_ok_with_a_recent_good_backup()
    {
        var h = BackupHealth.Evaluate(true, Good(7), Good(7), Now.AddDays(-30), Now);
        Assert.Equal(BackupHealthState.Ok, h.State);
        Assert.False(h.Alarm);
        Assert.Null(h.DigestWarning);
        Assert.Contains("5 MB", h.Text);
    }

    [Fact]
    public void A_failed_backup_alarms_at_once_but_the_digest_waits_for_48_hours()
    {
        var h = BackupHealth.Evaluate(true, Bad(1), Good(25), Now.AddDays(-30), Now);
        Assert.Equal(BackupHealthState.Failed, h.State);
        Assert.True(h.Alarm);
        Assert.Null(h.DigestWarning);
        Assert.Contains("connection refused", h.Text);

        var old = BackupHealth.Evaluate(true, Bad(1), Good(49), Now.AddDays(-30), Now);
        Assert.Equal(BackupHealthState.Failed, old.State);
        Assert.NotNull(old.DigestWarning);
    }

    [Fact]
    public void A_good_backup_older_than_48_hours_is_stale()
    {
        var h = BackupHealth.Evaluate(true, Good(50), Good(50), Now.AddDays(-30), Now);
        Assert.Equal(BackupHealthState.Stale, h.State);
        Assert.True(h.Alarm);
        Assert.Contains("2 days ago", h.DigestWarning);
        Assert.Equal(BackupHealthState.Ok, BackupHealth.Evaluate(true, Good(47), Good(47), Now.AddDays(-30), Now).State);
    }

    [Fact]
    public void A_new_install_is_given_two_nights_before_no_backup_is_an_alarm()
    {
        Assert.Equal(BackupHealthState.Waiting, BackupHealth.Evaluate(true, null, null, null, Now).State);
        Assert.Equal(BackupHealthState.Waiting, BackupHealth.Evaluate(true, null, null, Now.AddHours(-20), Now).State);
        var late = BackupHealth.Evaluate(true, null, null, Now.AddHours(-49), Now);
        Assert.Equal(BackupHealthState.Stale, late.State);
        Assert.Contains("No good backup has ever been taken", late.DigestWarning);
    }

    [Fact]
    public void Backups_switched_off_do_not_alarm()
    {
        var h = BackupHealth.Evaluate(false, Good(500), Good(500), Now.AddDays(-30), Now);
        Assert.Equal(BackupHealthState.Disabled, h.State);
        Assert.False(h.Alarm);
        Assert.Null(h.DigestWarning);
    }

    // ---- the archive (SQLite, for real)

    private async Task SeedAsync()
    {
        await using var db = _host.Db.CreateDbContext();
        db.Watchlist.Add(new WatchlistEntry { Id = Guid.NewGuid(), Vendor = "Fortinet", Product = "FortiOS", VendorNorm = "fortinet", ProductNorm = "fortios", Version = "7.2.5", CreatedAt = DateTime.UtcNow, UpdatedAt = DateTime.UtcNow });
        await db.SaveChangesAsync();
    }

    private static async Task<Dictionary<string, byte[]>> ReadArchiveAsync(string path, string? passphrase = null)
    {
        var entries = new Dictionary<string, byte[]>();
        await using var file = File.OpenRead(path);
        Stream source = passphrase is null ? file : new BackupCrypto.DecryptingStream(file, passphrase);
        await using var gz = new GZipStream(source, CompressionMode.Decompress);
        await using var tar = new TarReader(gz);
        while (await tar.GetNextEntryAsync() is { } e)
        {
            using var ms = new MemoryStream();
            if (e.DataStream is not null) await e.DataStream.CopyToAsync(ms);
            entries[e.Name] = ms.ToArray();
        }
        return entries;
    }

    [Fact]
    public async Task A_backup_holds_the_database_and_the_keys_and_restores()
    {
        await SeedAsync();
        var backups = Service();

        var r = await backups.RunAsync("manual", "admin");

        Assert.True(r.Ok, r.Error);
        Assert.False(r.Encrypted);
        var path = Path.Combine(backups.BackupDir, r.File!);
        Assert.Equal(new FileInfo(path).Length, r.Bytes);
        Assert.NotNull(BackupFile.Parse(r.File!));
        // written whole or not at all: nothing temporary is left, in the folder or in the work area
        Assert.Equal(new[] { r.File }, Directory.GetFiles(backups.BackupDir).Select(Path.GetFileName));
        Assert.Empty(Directory.GetDirectories(Path.Combine(_host.DataDir, "backup-work")));

        var manifest = await BackupArchive.VerifyAsync(path, null, CancellationToken.None);
        Assert.Equal("sqlite", manifest.Provider);
        Assert.Equal(2, manifest.Keys);
        Assert.Equal("manual", manifest.Kind);

        var entries = await ReadArchiveAsync(path);
        Assert.Equal(new[] { "manifest.json", "keys/key-1.xml", "keys/key-2.xml", "database.sqlite" }, entries.Keys);
        Assert.Equal("<key id=\"1\"/>", Encoding.UTF8.GetString(entries["keys/key-1.xml"]));

        // the restore: the copy opens as a database and holds the row
        var restored = Path.Combine(_host.DataDir, "restored.db");
        await File.WriteAllBytesAsync(restored, entries["database.sqlite"]);
        await using var conn = new SqliteConnection("Data Source=" + restored + ";Pooling=false");
        await conn.OpenAsync();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT Product FROM Watchlist";
        Assert.Equal("FortiOS", (string?)await cmd.ExecuteScalarAsync());

        // recorded, audited, and healthy
        var history = await backups.HistoryAsync();
        Assert.Single(history);
        Assert.True(history[0].Ok);
        Assert.Equal(BackupHealthState.Ok, (await backups.HealthAsync()).State);
        await using var db = _host.Db.CreateDbContext();
        Assert.Contains(db.Audit, a => a.Action == "backup.run" && a.Actor == "admin" && a.Target == r.File);
    }

    [Fact]
    public async Task An_encrypted_backup_needs_its_passphrase()
    {
        await SeedAsync();
        var backups = Service();
        await Assert.ThrowsAsync<ArgumentException>(() => backups.SetPassphraseAsync("short", "admin"));
        await backups.SetPassphraseAsync("correct horse battery staple", "admin");
        Assert.True((await backups.LoadOptionsAsync()).Encrypt);
        // the passphrase is stored protected, and the audit log does not hold it
        await using (var db = _host.Db.CreateDbContext())
        {
            var row = db.Settings.Single(s => s.Key == BackupService.PassphraseKey);
            Assert.True(row.Encrypted);
            Assert.DoesNotContain("correct horse", row.Value);
            Assert.DoesNotContain(db.Audit, a => (a.After ?? "").Contains("correct horse"));
        }

        var r = await backups.RunAsync("manual", "admin");

        Assert.True(r.Ok, r.Error);
        Assert.True(r.Encrypted);
        Assert.EndsWith(".vvbak.enc", r.File);
        var path = Path.Combine(backups.BackupDir, r.File!);
        Assert.True(BackupCrypto.IsEncryptedFile(path));
        // nothing readable in the file: not the gzip header, not the key material, not the SQLite header
        var raw = await File.ReadAllBytesAsync(path);
        Assert.Equal(-1, raw.AsSpan().IndexOf("SQLite format 3"u8));
        Assert.Equal(-1, raw.AsSpan().IndexOf("<key id="u8));

        await Assert.ThrowsAsync<InvalidDataException>(() => BackupArchive.VerifyAsync(path, null, CancellationToken.None));
        var wrong = await Assert.ThrowsAsync<CryptographicException>(() => BackupArchive.VerifyAsync(path, "another passphrase entirely", CancellationToken.None));
        Assert.Contains("Wrong passphrase", wrong.Message);
        var manifest = await BackupArchive.VerifyAsync(path, "correct horse battery staple", CancellationToken.None);
        Assert.Equal(2, manifest.Keys);
        Assert.Contains("database.sqlite", (await ReadArchiveAsync(path, "correct horse battery staple")).Keys);
    }

    [Fact]
    public void Encryption_detects_damage_truncation_and_trailing_data()
    {
        var plain = RandomNumberGenerator.GetBytes(3 * BackupCrypto.ChunkSize + 12345);
        byte[] Encrypt(byte[] data)
        {
            using var ms = new MemoryStream();
            using (var enc = new BackupCrypto.EncryptingStream(ms, "a long enough passphrase", 1000))
            {
                // odd-sized writes, so chunk boundaries fall mid-write
                for (var i = 0; i < data.Length; i += 70001) enc.Write(data, i, Math.Min(70001, data.Length - i));
                enc.Complete();
            }
            return ms.ToArray();
        }
        static byte[] Decrypt(byte[] cipher, string pass = "a long enough passphrase")
        {
            using var dec = new BackupCrypto.DecryptingStream(new MemoryStream(cipher), pass);
            using var ms = new MemoryStream();
            dec.CopyTo(ms);
            return ms.ToArray();
        }

        var cipher = Encrypt(plain);
        Assert.Equal(plain, Decrypt(cipher));
        Assert.Empty(Decrypt(Encrypt(Array.Empty<byte>())));
        Assert.Equal(new byte[BackupCrypto.ChunkSize], Decrypt(Encrypt(new byte[BackupCrypto.ChunkSize])));
        // the same plaintext never encrypts to the same bytes (fresh salt and nonce)
        Assert.NotEqual(cipher, Encrypt(plain));

        Assert.Throws<CryptographicException>(() => Decrypt(cipher, "the wrong passphrase"));
        var flipped = (byte[])cipher.Clone(); flipped[cipher.Length / 2] ^= 1;
        Assert.Throws<CryptographicException>(() => Decrypt(flipped));
        var header = (byte[])cipher.Clone(); header[20] ^= 1;
        Assert.Throws<CryptographicException>(() => Decrypt(header));
        // cut at a frame boundary: every remaining frame is intact, but none is marked final
        var frame = 5 + BackupCrypto.ChunkSize + 16;
        Assert.Throws<CryptographicException>(() => Decrypt(cipher[..(BackupCrypto.HeaderLength + 2 * frame)]));
        Assert.Throws<CryptographicException>(() => Decrypt(cipher[..^1]));
        Assert.Throws<CryptographicException>(() => Decrypt(cipher.Concat(new byte[] { 0 }).ToArray()));
        // frames swapped
        var swapped = (byte[])cipher.Clone();
        Array.Copy(cipher, BackupCrypto.HeaderLength, swapped, BackupCrypto.HeaderLength + frame, frame);
        Array.Copy(cipher, BackupCrypto.HeaderLength + frame, swapped, BackupCrypto.HeaderLength, frame);
        Assert.Throws<CryptographicException>(() => Decrypt(swapped));
    }

    [Fact]
    public async Task A_damaged_archive_does_not_verify()
    {
        await SeedAsync();
        var backups = Service();
        var r = await backups.RunAsync("manual", "admin");
        var path = Path.Combine(backups.BackupDir, r.File!);
        var bytes = await File.ReadAllBytesAsync(path);
        await File.WriteAllBytesAsync(path, bytes[..(bytes.Length / 2)]);
        await Assert.ThrowsAnyAsync<Exception>(() => BackupArchive.VerifyAsync(path, null, CancellationToken.None));
    }

    [Fact]
    public async Task The_restore_scripts_command_line_decrypts_and_verifies()
    {
        await SeedAsync();
        var backups = Service();
        await backups.SetPassphraseAsync("correct horse battery staple", "admin");
        var r = await backups.RunAsync("manual", "admin");
        var encrypted = Path.Combine(backups.BackupDir, r.File!);
        var plain = Path.Combine(_host.DataDir, "plain.vvbak");

        // anything else on the command line is not for the backup tool: the console starts as usual
        Assert.False(await BackupCli.TryRunAsync(Array.Empty<string>()));
        Assert.False(await BackupCli.TryRunAsync(new[] { "--urls", "http://localhost:5000" }));

        var before = Environment.GetEnvironmentVariable(BackupCli.PassphraseVariable);
        var exit = Environment.ExitCode;
        try
        {
            Environment.SetEnvironmentVariable(BackupCli.PassphraseVariable, "the wrong passphrase");
            Assert.True(await BackupCli.TryRunAsync(new[] { "backup-decrypt", encrypted, plain }));
            Assert.Equal(1, Environment.ExitCode);
            Assert.False(File.Exists(plain));

            Environment.ExitCode = 0;
            Environment.SetEnvironmentVariable(BackupCli.PassphraseVariable, "correct horse battery staple");
            Assert.True(await BackupCli.TryRunAsync(new[] { "backup-decrypt", encrypted, plain }));
            Assert.Equal(0, Environment.ExitCode);
            Assert.True(await BackupCli.TryRunAsync(new[] { "backup-verify", encrypted }));
            Assert.Equal(0, Environment.ExitCode);
        }
        finally
        {
            Environment.SetEnvironmentVariable(BackupCli.PassphraseVariable, before);
            Environment.ExitCode = exit;
        }
        // the decrypted file is an ordinary archive, readable without the console
        Assert.False(BackupCrypto.IsEncryptedFile(plain));
        Assert.Equal(2, (await BackupArchive.VerifyAsync(plain, null, CancellationToken.None)).Keys);
    }

    [Fact]
    public async Task The_worker_takes_one_backup_a_night_and_not_at_start_up()
    {
        await SeedAsync();
        var backups = Service();
        var services = new Microsoft.Extensions.DependencyInjection.ServiceCollection();
        Microsoft.Extensions.DependencyInjection.ServiceCollectionServiceExtensions.AddSingleton(services, backups);
        Microsoft.Extensions.DependencyInjection.ServiceCollectionServiceExtensions.AddSingleton(services, _host.Settings);
        await using var sp = Microsoft.Extensions.DependencyInjection.ServiceCollectionContainerBuilderExtensions.BuildServiceProvider(services);

        // first pass of a new console: nothing yet, the first backup waits for its scheduled time
        await BackupService.RunIfDueAsync(sp, CancellationToken.None);
        Assert.Empty(backups.List());
        Assert.Equal(BackupHealthState.Waiting, (await backups.HealthAsync()).State);

        // two days on, the scheduled time has passed: one backup, and a second pass the same night takes no other
        await _host.Settings.SetStateAsync(BackupService.FirstCheckKey, DateTime.UtcNow.AddDays(-2).ToString("O"));
        await BackupService.RunIfDueAsync(sp, CancellationToken.None);
        await BackupService.RunIfDueAsync(sp, CancellationToken.None);
        var file = Assert.Single(backups.List()).File;
        Assert.Equal("scheduled", file.Kind);
        Assert.Equal(BackupHealthState.Ok, (await backups.HealthAsync()).State);

        // switched off: no more
        await backups.SaveOptionsAsync(new BackupOptions { Enabled = false }, "admin");
        await _host.Settings.SetStateAsync(BackupService.LastOkKey, null);
        await BackupService.RunIfDueAsync(sp, CancellationToken.None);
        Assert.Single(backups.List());
    }

    // ---- failure

    [Fact]
    public async Task A_failed_backup_leaves_no_file_is_recorded_and_costs_no_older_backup()
    {
        await SeedAsync();
        var backups = Service();
        await backups.SaveOptionsAsync(new BackupOptions { KeepDaily = 1, KeepWeekly = 0 }, "admin");
        var good = await backups.RunAsync("manual", "admin");
        Assert.True(good.Ok, good.Error);

        // a passphrase the key ring can no longer read: the backup must fail, not fall back to an unencrypted archive
        await _host.Settings.SetStateAsync(BackupService.PassphraseKey, "not-protected-by-this-key-ring");
        var bad = await backups.RunAsync("scheduled", "system");

        Assert.False(bad.Ok);
        Assert.Contains("passphrase", bad.Error);
        Assert.Equal(new[] { good.File }, Directory.GetFiles(backups.BackupDir).Select(Path.GetFileName));
        var history = await backups.HistoryAsync();
        Assert.Equal(new[] { false, true }, history.Select(h => h.Ok));
        var health = await backups.HealthAsync();
        Assert.Equal(BackupHealthState.Failed, health.State);
        Assert.True(health.Alarm);
        Assert.Equal(good.File, health.LastOk!.File);
        await using var db = _host.Db.CreateDbContext();
        Assert.Contains(db.Audit, a => a.Action == "backup.failed");
    }

    [Fact]
    public async Task A_good_backup_prunes_to_the_retention()
    {
        await SeedAsync();
        var backups = Service();
        await backups.SaveOptionsAsync(new BackupOptions { KeepDaily = 2, KeepWeekly = 0 }, "admin");
        Directory.CreateDirectory(backups.BackupDir);
        foreach (var day in new[] { 3, 10, 20 })
            await File.WriteAllTextAsync(Path.Combine(backups.BackupDir, BackupFile.NameFor(DateTime.UtcNow.AddDays(-day), "scheduled", false)), "old");
        await File.WriteAllTextAsync(Path.Combine(backups.BackupDir, "notes.txt"), "not ours");

        var r = await backups.RunAsync("scheduled", "system");

        Assert.True(r.Ok, r.Error);
        var left = backups.List().Select(x => x.File).ToList();
        Assert.Equal(2, left.Count);
        Assert.Equal(r.File, left[0].Name);
        Assert.True(File.Exists(Path.Combine(backups.BackupDir, "notes.txt")));
    }

    [Fact]
    public async Task Settings_are_validated_and_survive_a_save_of_the_settings_page()
    {
        var backups = Service();
        var o = await backups.LoadOptionsAsync();
        Assert.True(o.Enabled);
        Assert.Equal("02:30", o.Time);
        Assert.Equal((14, 8), (o.KeepDaily, o.KeepWeekly));
        await Assert.ThrowsAsync<ArgumentException>(() => backups.SaveOptionsAsync(new BackupOptions { Time = "half past two" }, "admin"));
        await Assert.ThrowsAsync<ArgumentException>(() => backups.SaveOptionsAsync(new BackupOptions { KeepDaily = 0 }, "admin"));

        await backups.SaveOptionsAsync(new BackupOptions { Enabled = false, Time = "3:05", KeepDaily = 7, KeepWeekly = 4 }, "admin");
        await _host.Settings.SaveAsync(new AppSettings { OrganisationName = "Example Ltd" }, "admin");

        o = await backups.LoadOptionsAsync();
        Assert.False(o.Enabled);
        Assert.Equal("03:05", o.Time);
        Assert.Equal((7, 4), (o.KeepDaily, o.KeepWeekly));
        Assert.Equal(BackupHealthState.Disabled, (await backups.HealthAsync()).State);
    }

    [Fact]
    public async Task The_digest_footer_warns_only_when_the_last_good_backup_is_older_than_48_hours()
    {
        var now = DateTime.UtcNow;
        async Task<string?> WarningAsync() => (await BackupService.HealthAsync(_host.Settings, null, now)).DigestWarning;
        await _host.Settings.SetStateAsync(BackupService.FirstCheckKey, now.AddDays(-10).ToString("O"));
        Assert.NotNull(await WarningAsync());

        var fresh = new BackupResult(now.AddHours(-20), true, "scheduled", "x.vvbak", 1000, 1, null, false);
        await _host.Settings.SetStateAsync(BackupService.LastOkKey, System.Text.Json.JsonSerializer.Serialize(fresh));
        await _host.Settings.SetStateAsync(BackupService.HistoryKey, System.Text.Json.JsonSerializer.Serialize(new[] { fresh }));
        Assert.Null(await WarningAsync());

        var old = fresh with { At = now.AddHours(-60) };
        await _host.Settings.SetStateAsync(BackupService.LastOkKey, System.Text.Json.JsonSerializer.Serialize(old));
        await _host.Settings.SetStateAsync(BackupService.HistoryKey, System.Text.Json.JsonSerializer.Serialize(new[] { old }));
        Assert.Contains("overdue", await WarningAsync());

        var html = DigestService.RenderHtml(new DigestContent { BackupWarning = await WarningAsync() }, "", now);
        Assert.Contains("Database backup is overdue", html);
        Assert.Contains("Database backup is overdue", DigestService.RenderText(new DigestContent { BackupWarning = await WarningAsync() }, "", now));
        Assert.DoesNotContain("Database backup", DigestService.RenderHtml(new DigestContent(), "", now));
    }

    // ---- Postgres, with pg_dump and pg_restore stood in for

    [Fact]
    public async Task Postgres_is_dumped_with_the_password_in_the_environment_and_the_dump_is_listed()
    {
        var backups = Service();
        var calls = new List<(string File, IReadOnlyList<string> Args, IReadOnlyDictionary<string, string> Env)>();
        var dump = Path.Combine(_host.DataDir, "database.dump");
        backups.RunProcess = (file, args, env, _) =>
        {
            calls.Add((file, args, env));
            if (file == "pg_dump") File.WriteAllText(dump, "PGDMP");
            return Task.FromResult((0, file == "pg_restore" ? "; Archive created\n3521; 0 16390 TABLE DATA public Verdicts vulnverdict\n" : ""));
        };

        await backups.DumpPostgresAsync("Host=db;Port=5433;Database=vulnverdict;Username=vv;Password=s3cret-db-password", dump);

        Assert.Equal(new[] { "pg_dump", "pg_restore" }, calls.Select(c => c.File));
        var pgDump = calls[0];
        Assert.Contains("--format=custom", pgDump.Args);
        Assert.Contains("--host=db", pgDump.Args);
        Assert.Contains("--port=5433", pgDump.Args);
        Assert.Contains("--username=vv", pgDump.Args);
        Assert.Contains("--dbname=vulnverdict", pgDump.Args);
        Assert.Contains("--no-password", pgDump.Args);
        Assert.DoesNotContain(pgDump.Args, a => a.Contains("s3cret"));
        Assert.Equal("s3cret-db-password", pgDump.Env["PGPASSWORD"]);
        Assert.Equal(new[] { "--list", dump }, calls[1].Args);
    }

    [Theory]
    [InlineData(1, 0, "", "pg_dump failed")]
    [InlineData(0, 1, "", "did not verify")]
    [InlineData(0, 0, "; Archive created, no entries\n", "no table data")]
    public async Task A_postgres_dump_that_fails_or_does_not_list_is_not_a_backup(int dumpExit, int listExit, string listing, string expected)
    {
        var backups = Service();
        var dump = Path.Combine(_host.DataDir, "database.dump");
        backups.RunProcess = (file, _, _, _) =>
        {
            if (file == "pg_dump" && dumpExit == 0) File.WriteAllText(dump, "PGDMP");
            return Task.FromResult(file == "pg_dump" ? (dumpExit, "connection to server failed") : (listExit, listing));
        };
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => backups.DumpPostgresAsync("Host=/var/run/postgresql;Database=vulnverdict;Username=vulnverdict", dump));
        Assert.Contains(expected, ex.Message);
    }
}

