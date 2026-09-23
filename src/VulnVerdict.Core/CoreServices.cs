using System.Net.Http.Headers;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Digest;
using VulnVerdict.Core.Engine;
using VulnVerdict.Core.Feeds;
using VulnVerdict.Core.Services;

namespace VulnVerdict.Core;

public static class CoreServices
{
    /// <summary>
    /// Registers the database (Postgres or SQLite), feeds, engine services and optionally the worker.
    /// provider: "postgres" | "sqlite". role: "all" | "web" | "worker".
    /// </summary>
    public static IServiceCollection AddVulnVerdictCore(this IServiceCollection services, string provider, string connectionString, WorkerOptions worker, string role)
    {
        services.AddDbContextFactory<VvDbContext>(o =>
        {
            if (provider.Equals("postgres", StringComparison.OrdinalIgnoreCase) || provider.Equals("postgresql", StringComparison.OrdinalIgnoreCase))
                o.UseNpgsql(connectionString, n => n.CommandTimeout(300));
            else
                o.UseSqlite(connectionString, s => s.CommandTimeout(300));
        });
        // scoped DbContext resolved from the factory for components that prefer it
        services.AddScoped(sp => sp.GetRequiredService<IDbContextFactory<VvDbContext>>().CreateDbContext());

        services.AddSingleton(worker);
        services.AddHttpClient("feeds", c =>
        {
            c.Timeout = TimeSpan.FromMinutes(30);
            c.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("VulnVerdict", "0.1"));
            c.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            c.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("*/*"));
        });

        services.AddHttpClient("mail", c =>
        {
            c.Timeout = TimeSpan.FromSeconds(30);
            c.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("VulnVerdict", "0.1"));
        });

        services.AddSingleton<SettingsService>();
        services.AddSingleton<EmailService>();
        services.AddSingleton<VerdictEvaluator>();
        services.AddSingleton<VerdictWorkflow>();
        services.AddSingleton<WatchlistService>();
        services.AddSingleton<DigestService>();

        services.AddSingleton<IFeed, KevFeed>();
        services.AddSingleton<IFeed, EpssFeed>();
        services.AddSingleton<IFeed, ExploitDbFeed>();
        services.AddSingleton<IFeed, MetasploitFeed>();
        services.AddSingleton<IFeed, NucleiFeed>();
        services.AddSingleton<IFeed>(_ => new CveListFeed { MinYear = worker.CveMinYear });

        if (role is "all" or "worker") services.AddHostedService<WorkerService>();
        if (role is "all" or "web") services.AddHostedService<WorkerMonitorService>();
        return services;
    }

    /// <summary>Create the schema and seed the alias table. EnsureCreated is used for the MVP; migrations come with phase 3.</summary>
    public static async Task InitialiseDatabaseAsync(IServiceProvider sp, CancellationToken ct = default)
    {
        var factory = sp.GetRequiredService<IDbContextFactory<VvDbContext>>();
        await using var db = await factory.CreateDbContextAsync(ct);
        if (db.Database.IsSqlite())
        {
            await db.Database.EnsureCreatedAsync(ct);
            await db.Database.ExecuteSqlRawAsync("PRAGMA journal_mode=WAL;", ct);
        }
        else
        {
            // wait for Postgres to accept connections (Compose start-up)
            for (var i = 0; i < 30; i++)
            {
                try { await db.Database.EnsureCreatedAsync(ct); break; }
                catch when (i < 29) { await Task.Delay(2000, ct); }
            }
        }
        if (!await db.Aliases.AnyAsync(ct))
        {
            db.Aliases.AddRange(SeedAliases.Select(a => new ProductAlias { AliasNorm = Normalizer.Norm(a.Alias), VendorNorm = Normalizer.Norm(a.Vendor), ProductNorm = Normalizer.Norm(a.Product) }));
            await db.SaveChangesAsync(ct);
        }
    }

    /// <summary>Common display names mapped to the CNA vendor/product spelling. Grown by the needs-mapping queue in phase 3.</summary>
    private static readonly (string Alias, string Vendor, string Product)[] SeedAliases =
    {
        ("FortiGate", "Fortinet", "FortiOS"),
        ("FortiGate firewall", "Fortinet", "FortiOS"),
        ("Fortinet FortiGate", "Fortinet", "FortiOS"),
        ("FortiClient EMS", "Fortinet", "FortiClientEMS"),
        ("FortiClient Enterprise Management Server", "Fortinet", "FortiClientEMS"),
        ("Windows Server 2019", "Microsoft", "Windows Server 2019"),
        ("Windows Server 2022", "Microsoft", "Windows Server 2022"),
        ("Windows Server 2025", "Microsoft", "Windows Server 2025"),
        ("Exchange Server", "Microsoft", "Microsoft Exchange Server 2019 Cumulative Update 14"),
        ("vCenter", "VMware", "vCenter Server"),
        ("VMware vCenter", "VMware", "vCenter Server"),
        ("ESXi", "VMware", "ESXi"),
        ("VMware ESXi", "VMware", "ESXi"),
        ("Cisco ASA", "Cisco", "Cisco Adaptive Security Appliance (ASA) Software"),
        ("Cisco IOS XE", "Cisco", "Cisco IOS XE Software"),
        ("Palo Alto PAN-OS", "Palo Alto Networks", "PAN-OS"),
        ("SonicOS", "SonicWall", "SonicOS"),
        ("GlobalProtect", "Palo Alto Networks", "GlobalProtect App"),
        ("Ivanti Connect Secure", "Ivanti", "Connect Secure"),
        ("Citrix NetScaler", "Citrix", "NetScaler ADC"),
        ("NetScaler Gateway", "Citrix", "NetScaler Gateway"),
        ("Veeam Backup & Replication", "Veeam", "Backup & Replication"),
        ("Veeam", "Veeam", "Backup & Replication"),
        ("SQL Server 2019", "Microsoft", "Microsoft SQL Server 2019 (GDR)"),
        ("SQL Server 2022", "Microsoft", "Microsoft SQL Server 2022 (GDR)"),
        ("IIS", "Microsoft", "Internet Information Services"),
        ("Apache", "Apache Software Foundation", "Apache HTTP Server"),
        ("Apache httpd", "Apache Software Foundation", "Apache HTTP Server"),
        ("nginx", "F5", "NGINX Open Source"),
        ("OpenSSH", "OpenBSD", "OpenSSH"),
        ("Chrome", "Google", "Chrome"),
        ("Google Chrome", "Google", "Chrome"),
        ("Firefox", "Mozilla", "Firefox"),
        ("Ubiquiti UniFi", "Ubiquiti", "UniFi Network Application"),
        ("UniFi", "Ubiquiti", "UniFi Network Application"),
        ("Synology DSM", "Synology", "DiskStation Manager (DSM)"),
        ("QNAP QTS", "QNAP Systems Inc.", "QTS"),
        ("ConnectWise ScreenConnect", "ConnectWise", "ScreenConnect"),
        ("ScreenConnect", "ConnectWise", "ScreenConnect"),
        ("PaperCut", "PaperCut", "PaperCut NG, PaperCut MF"),
        ("3CX", "3CX", "3CX"),
        ("MOVEit Transfer", "Progress Software Corporation", "MOVEit Transfer"),
        ("Telerik UI for ASP.NET AJAX", "Progress Software Corporation", "Telerik UI for ASP.NET AJAX"),
        ("GitLab", "GitLab", "GitLab"),
        ("Jenkins", "Jenkins Project", "Jenkins"),
        ("Atlassian Confluence", "Atlassian", "Confluence Data Center"),
        ("Confluence", "Atlassian", "Confluence Data Center"),
        ("Jira", "Atlassian", "Jira Software Data Center"),
        ("Zimbra", "Zimbra", "Zimbra Collaboration Suite"),
        ("WordPress", "WordPress", "WordPress"),
        ("Ollama", "ollama", "ollama"),
    };
}

/// <summary>Section 3 rule 8: the console emails the administrator if the worker stops working.</summary>
public sealed class WorkerMonitorService : BackgroundService
{
    private readonly IServiceProvider _sp;
    private readonly ILogger<WorkerMonitorService> _log;

    public WorkerMonitorService(IServiceProvider sp, ILogger<WorkerMonitorService> log) { _sp = sp; _log = log; }

    public static async Task<(bool Alive, DateTime? LastBeat)> WorkerStatusAsync(SettingsService settings, CancellationToken ct = default)
    {
        var s = await settings.GetStateAsync(SettingsService.Keys.WorkerHeartbeat, ct);
        if (s is null || !DateTime.TryParse(s, null, System.Globalization.DateTimeStyles.RoundtripKind, out var d)) return (false, null);
        return (DateTime.UtcNow - d < TimeSpan.FromMinutes(10), d);
    }

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        await Task.Delay(TimeSpan.FromMinutes(15), ct).ContinueWith(_ => { }, CancellationToken.None);
        while (!ct.IsCancellationRequested)
        {
            try
            {
                using var scope = _sp.CreateScope();
                var settings = scope.ServiceProvider.GetRequiredService<SettingsService>();
                var (alive, last) = await WorkerStatusAsync(settings, ct);
                if (!alive)
                {
                    var lastAlert = await settings.GetStateAsync(SettingsService.Keys.LastWorkerStaleAlert, ct);
                    if (lastAlert is null || !DateTime.TryParse(lastAlert, null, System.Globalization.DateTimeStyles.RoundtripKind, out var la) || DateTime.UtcNow - la > TimeSpan.FromHours(24))
                    {
                        _log.LogWarning("Worker heartbeat stale (last {Last})", last);
                        await WorkerService.AdminAlertAsync(scope.ServiceProvider, "Worker has stopped",
                            "The VulnVerdict worker last reported at " + (last?.ToString("u") ?? "never") + ". Feeds, verdicts and digests are not being updated until it is restarted.", ct);
                        await settings.SetStateAsync(SettingsService.Keys.LastWorkerStaleAlert, DateTime.UtcNow.ToString("O"), ct);
                    }
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
            catch (Exception ex) { _log.LogError(ex, "Worker monitor error"); }
            try { await Task.Delay(TimeSpan.FromMinutes(5), ct); } catch (OperationCanceledException) { }
        }
    }
}
