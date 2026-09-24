using System.Net.Http.Headers;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using VulnVerdict.Core.Adapters;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Digest;
using VulnVerdict.Core.Engine;
using VulnVerdict.Core.Feeds;
using VulnVerdict.Core.Services;

namespace VulnVerdict.Core;

public static class CoreServices
{
    /// <summary>
    /// Registers the database (Postgres or SQLite, each with its own migrations), feeds, adapters, engine services and
    /// optionally the worker. provider: "postgres" | "sqlite". role: "all" | "web" | "worker".
    /// </summary>
    public static IServiceCollection AddVulnVerdictCore(this IServiceCollection services, string provider, string connectionString, WorkerOptions worker, string role)
    {
        var postgres = provider.Equals("postgres", StringComparison.OrdinalIgnoreCase) || provider.Equals("postgresql", StringComparison.OrdinalIgnoreCase);
        // both contexts are registered so design-time tooling can generate migrations for either provider
        services.AddDbContextFactory<SqliteVvDbContext>(o => o.UseSqlite(postgres ? "Data Source=:memory:" : connectionString, s => s.CommandTimeout(300)));
        services.AddDbContextFactory<PostgresVvDbContext>(o => o.UseNpgsql(postgres ? connectionString : "Host=localhost;Database=design", n => n.CommandTimeout(300)));
        services.AddSingleton<IDbContextFactory<VvDbContext>>(sp => postgres
            ? new ContextFactory<PostgresVvDbContext>(sp.GetRequiredService<IDbContextFactory<PostgresVvDbContext>>())
            : new ContextFactory<SqliteVvDbContext>(sp.GetRequiredService<IDbContextFactory<SqliteVvDbContext>>()));
        services.AddScoped(sp => sp.GetRequiredService<IDbContextFactory<VvDbContext>>().CreateDbContext());

        services.AddSingleton(worker);
        services.AddHttpClient("feeds", c =>
        {
            c.Timeout = TimeSpan.FromMinutes(30);
            c.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("VulnVerdict", "0.2"));
            c.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            c.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("*/*"));
        });
        services.AddHttpClient("mail", c =>
        {
            c.Timeout = TimeSpan.FromSeconds(30);
            c.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("VulnVerdict", "0.2"));
        });
        services.AddHttpClient("llm", c =>
        {
            c.Timeout = TimeSpan.FromMinutes(3);
            c.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("VulnVerdict", "0.2"));
        });
        // adapters talk to customer systems that often have private certificates; the connector form has a "verify TLS" switch
        services.AddHttpClient("adapter", c =>
        {
            c.Timeout = TimeSpan.FromMinutes(5);
            c.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("VulnVerdict", "0.2"));
        });
        services.AddHttpClient("adapter-insecure", c =>
        {
            c.Timeout = TimeSpan.FromMinutes(5);
            c.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("VulnVerdict", "0.2"));
        }).ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler { ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator });

        services.AddSingleton<SettingsService>();
        services.AddSingleton<EmailService>();
        services.AddSingleton<VerdictEvaluator>();
        services.AddSingleton<VerdictWorkflow>();
        services.AddSingleton<WatchlistService>();
        services.AddSingleton<DigestService>();
        services.AddSingleton<ReportService>();
        services.AddSingleton<LlmService>();
        services.AddSingleton<InventoryService>();
        services.AddSingleton<ConnectorService>();
        // phase 5: signed bundles, licence, telemetry, MSP reporting
        services.AddSingleton<BundleService>();
        services.AddSingleton<LicenseService>();
        services.AddSingleton<TelemetryService>();
        services.AddSingleton<MspReportService>();

        services.AddSingleton<IFeed, KevFeed>();
        services.AddSingleton<IFeed, EpssFeed>();
        services.AddSingleton<IFeed, ExploitDbFeed>();
        services.AddSingleton<IFeed, MetasploitFeed>();
        services.AddSingleton<IFeed, NucleiFeed>();
        services.AddSingleton<IFeed>(_ => new CveListFeed { MinYear = worker.CveMinYear });

        AdapterRegistry.Register(services);

        if (role is "all" or "worker") services.AddHostedService<WorkerService>();
        if (role is "all" or "web") services.AddHostedService<WorkerMonitorService>();
        return services;
    }

    private sealed class ContextFactory<T> : IDbContextFactory<VvDbContext> where T : VvDbContext
    {
        private readonly IDbContextFactory<T> _inner;
        public ContextFactory(IDbContextFactory<T> inner) => _inner = inner;
        public VvDbContext CreateDbContext() => _inner.CreateDbContext();
        public async Task<VvDbContext> CreateDbContextAsync(CancellationToken ct = default) => await _inner.CreateDbContextAsync(ct);
    }

    /// <summary>Apply migrations (waiting for Postgres to come up on Compose start) and seed the alias table.</summary>
    public static async Task InitialiseDatabaseAsync(IServiceProvider sp, CancellationToken ct = default)
    {
        var factory = sp.GetRequiredService<IDbContextFactory<VvDbContext>>();
        await using var db = await factory.CreateDbContextAsync(ct);
        for (var i = 0; i < 30; i++)
        {
            try { await db.Database.MigrateAsync(ct); break; }
            catch (Exception ex) when (i < 29 && !db.Database.IsSqlite())
            {
                sp.GetRequiredService<ILoggerFactory>().CreateLogger("Startup").LogWarning("Database not ready ({Error}); retrying", ex.Message);
                await Task.Delay(2000, ct);
            }
        }
        if (db.Database.IsSqlite()) await db.Database.ExecuteSqlRawAsync("PRAGMA journal_mode=WAL;", ct);
        if (!await db.Aliases.AnyAsync(ct))
        {
            db.Aliases.AddRange(SeedAliases.Select(a => new ProductAlias { AliasNorm = Normalizer.Norm(a.Alias), VendorNorm = Normalizer.Norm(a.Vendor), ProductNorm = Normalizer.Norm(a.Product) }));
            await db.SaveChangesAsync(ct);
        }
    }

    /// <summary>Common display names mapped to the CNA vendor/product spelling. Grown by the needs-mapping queue.</summary>
    public static readonly (string Alias, string Vendor, string Product)[] SeedAliases =
    {
        ("FortiGate", "Fortinet", "FortiOS"),
        ("FortiGate firewall", "Fortinet", "FortiOS"),
        ("Fortinet FortiGate", "Fortinet", "FortiOS"),
        ("FortiClient EMS", "Fortinet", "FortiClientEMS"),
        ("FortiClient Enterprise Management Server", "Fortinet", "FortiClientEMS"),
        ("FortiClient", "Fortinet", "FortiClientWindows"),
        ("FortiSwitch", "Fortinet", "FortiSwitch"),
        ("FortiAP", "Fortinet", "FortiAP"),
        ("Windows Server 2016", "Microsoft", "Windows Server 2016"),
        ("Windows Server 2019", "Microsoft", "Windows Server 2019"),
        ("Windows Server 2022", "Microsoft", "Windows Server 2022"),
        ("Windows Server 2025", "Microsoft", "Windows Server 2025"),
        ("Windows 10", "Microsoft", "Windows 10 Version 22H2"),
        ("Windows 11", "Microsoft", "Windows 11 Version 24H2"),
        ("Exchange Server", "Microsoft", "Microsoft Exchange Server 2019 Cumulative Update 14"),
        ("vCenter", "VMware", "vCenter Server"),
        ("VMware vCenter", "VMware", "vCenter Server"),
        ("VMware vCenter Server", "VMware", "vCenter Server"),
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
        ("Microsoft SQL Server", "Microsoft", "Microsoft SQL Server 2022 (GDR)"),
        ("IIS", "Microsoft", "Internet Information Services"),
        ("Internet Information Services", "Microsoft", "Internet Information Services"),
        ("Apache", "Apache Software Foundation", "Apache HTTP Server"),
        ("Apache httpd", "Apache Software Foundation", "Apache HTTP Server"),
        ("nginx", "F5", "NGINX Open Source"),
        ("OpenSSH", "OpenBSD", "OpenSSH"),
        ("Chrome", "Google", "Chrome"),
        ("Google Chrome", "Google", "Chrome"),
        ("Mozilla Firefox", "Mozilla", "Firefox"),
        ("Microsoft Edge", "Microsoft", "Microsoft Edge (Chromium-based)"),
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
        ("7-Zip", "7-Zip", "7-Zip"),
        ("Adobe Acrobat Reader DC", "Adobe", "Acrobat Reader"),
        ("Adobe Acrobat", "Adobe", "Acrobat Reader"),
        ("Notepad++", "Notepad++", "Notepad++"),
        ("VLC media player", "VideoLAN", "VLC"),
        ("Zoom", "Zoom Communications, Inc", "Zoom Workplace App"),
        ("Microsoft Teams", "Microsoft", "Microsoft Teams"),
        ("Microsoft Office", "Microsoft", "Microsoft 365 Apps for Enterprise"),
        ("Microsoft 365 Apps", "Microsoft", "Microsoft 365 Apps for Enterprise"),
        ("Docker Desktop", "Docker", "Docker Desktop"),
        ("PuTTY", "PuTTY", "PuTTY"),
        ("WinRAR", "RARLAB", "WinRAR"),
        ("Java", "Oracle Corporation", "Java SE JDK and JRE"),
        ("Oracle Java", "Oracle Corporation", "Java SE JDK and JRE"),
        ("Node.js", "Node.js", "Node"),
        ("Python", "Python Software Foundation", "CPython"),
        ("iDRAC", "Dell", "Integrated Dell Remote Access Controller 9"),
        ("iLO", "Hewlett Packard Enterprise (HPE)", "HPE Integrated Lights-Out 5 (iLO 5)"),
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
