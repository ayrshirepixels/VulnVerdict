using System;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace VulnVerdict.Core.Data.Migrations.Postgres
{
    /// <inheritdoc />
    public partial class Initial : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "Aliases",
                columns: table => new
                {
                    Id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    AliasNorm = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    VendorNorm = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    ProductNorm = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Aliases", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Assets",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    DisplayName = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    HostnamesJson = table.Column<string>(type: "text", nullable: false),
                    IpAddressesJson = table.Column<string>(type: "text", nullable: false),
                    MacAddressesJson = table.Column<string>(type: "text", nullable: false),
                    Kind = table.Column<int>(type: "integer", nullable: false),
                    OsVendor = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: true),
                    OsProduct = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    OsVersion = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    OsBuild = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    Criticality = table.Column<int>(type: "integer", nullable: false),
                    CriticalityPinned = table.Column<bool>(type: "boolean", nullable: false),
                    Exposure = table.Column<int>(type: "integer", nullable: false),
                    ExposureEvidence = table.Column<string>(type: "character varying(1000)", maxLength: 1000, nullable: true),
                    ExposurePinned = table.Column<bool>(type: "boolean", nullable: false),
                    Owner = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    FirstSeen = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    LastSeen = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    Unknown = table.Column<bool>(type: "boolean", nullable: false),
                    Archived = table.Column<bool>(type: "boolean", nullable: false),
                    Note = table.Column<string>(type: "character varying(1000)", maxLength: 1000, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Assets", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Audit",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    At = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    Actor = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    Action = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    Target = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    Before = table.Column<string>(type: "text", nullable: true),
                    After = table.Column<string>(type: "text", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Audit", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Bundles",
                columns: table => new
                {
                    Id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    Version = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    BuiltAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    AppliedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    Source = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    Signer = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Bundles", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "CnaProducts",
                columns: table => new
                {
                    VendorNorm = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    ProductNorm = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    Vendor = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    Product = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    CveCount = table.Column<int>(type: "integer", nullable: false),
                    LastSeen = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CnaProducts", x => new { x.VendorNorm, x.ProductNorm });
                });

            migrationBuilder.CreateTable(
                name: "Connectors",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    AdapterId = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    DisplayName = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    CredentialsJson = table.Column<string>(type: "text", nullable: false),
                    Enabled = table.Column<bool>(type: "boolean", nullable: false),
                    IntervalMinutes = table.Column<int>(type: "integer", nullable: false),
                    LastAttempt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    LastSuccess = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    LastError = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: true),
                    ConsecutiveFailures = table.Column<int>(type: "integer", nullable: false),
                    AssetsLastRun = table.Column<int>(type: "integer", nullable: false),
                    SoftwareLastRun = table.Column<int>(type: "integer", nullable: false),
                    RunRequested = table.Column<bool>(type: "boolean", nullable: false),
                    Running = table.Column<bool>(type: "boolean", nullable: false),
                    Progress = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Connectors", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Controls",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    AssetId = table.Column<Guid>(type: "uuid", nullable: true),
                    WatchlistEntryId = table.Column<Guid>(type: "uuid", nullable: true),
                    ProductNorm = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    Kind = table.Column<int>(type: "integer", nullable: false),
                    Description = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: false),
                    CreatedBy = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    Expiry = table.Column<DateTime>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Controls", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Cves",
                columns: table => new
                {
                    Id = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    State = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    Published = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    LastModified = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    Assigner = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    Title = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: true),
                    Description = table.Column<string>(type: "character varying(4000)", maxLength: 4000, nullable: true),
                    CvssV31Vector = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    CvssV31Score = table.Column<double>(type: "double precision", nullable: true),
                    CvssV40Vector = table.Column<string>(type: "character varying(300)", maxLength: 300, nullable: true),
                    CvssV40Score = table.Column<double>(type: "double precision", nullable: true),
                    SsvcExploitation = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: true),
                    SsvcAutomatable = table.Column<string>(type: "character varying(8)", maxLength: 8, nullable: true),
                    ReferencesJson = table.Column<string>(type: "text", nullable: true),
                    RetrievedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    SourceRef = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Cves", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "DigestRuns",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Kind = table.Column<int>(type: "integer", nullable: false),
                    GeneratedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    SentAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    Recipients = table.Column<string>(type: "character varying(1000)", maxLength: 1000, nullable: true),
                    Subject = table.Column<string>(type: "character varying(300)", maxLength: 300, nullable: false),
                    FixToday = table.Column<int>(type: "integer", nullable: false),
                    FixThisWeek = table.Column<int>(type: "integer", nullable: false),
                    NextPatchCycle = table.Column<int>(type: "integer", nullable: false),
                    Dismissed = table.Column<int>(type: "integer", nullable: false),
                    Html = table.Column<string>(type: "text", nullable: false),
                    Text = table.Column<string>(type: "text", nullable: false),
                    Error = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DigestRuns", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Epss",
                columns: table => new
                {
                    CveId = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    Score = table.Column<double>(type: "double precision", nullable: false),
                    Percentile = table.Column<double>(type: "double precision", nullable: false),
                    ScoreDate = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    RetrievedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Epss", x => x.CveId);
                });

            migrationBuilder.CreateTable(
                name: "ExploitSignals",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    CveId = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    Source = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    Title = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    Url = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: false),
                    PublishedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    RetrievedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ExploitSignals", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "FeedStatuses",
                columns: table => new
                {
                    Name = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    DisplayName = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    IntervalMinutes = table.Column<int>(type: "integer", nullable: false),
                    LastAttempt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    LastSuccess = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    LastError = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: true),
                    RecordsLastRun = table.Column<int>(type: "integer", nullable: false),
                    Cursor = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    RunRequested = table.Column<bool>(type: "boolean", nullable: false),
                    Running = table.Column<bool>(type: "boolean", nullable: false),
                    Progress = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_FeedStatuses", x => x.Name);
                });

            migrationBuilder.CreateTable(
                name: "Findings",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    AssetId = table.Column<Guid>(type: "uuid", nullable: false),
                    CveIdsJson = table.Column<string>(type: "text", nullable: false),
                    ConnectorId = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    Source = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    SourceSeverity = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    Title = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    RawRef = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    FirstSeen = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    LastSeen = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Findings", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Kev",
                columns: table => new
                {
                    CveId = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    VendorProject = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    Product = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    VulnerabilityName = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    DateAdded = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    RequiredAction = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: true),
                    DueDate = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    KnownRansomwareUse = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: true),
                    Notes = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: true),
                    RetrievedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Kev", x => x.CveId);
                });

            migrationBuilder.CreateTable(
                name: "Narratives",
                columns: table => new
                {
                    Key = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    Text = table.Column<string>(type: "text", nullable: false),
                    Provider = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    Model = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    PromptVersion = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Narratives", x => x.Key);
                });

            migrationBuilder.CreateTable(
                name: "PackageVulns",
                columns: table => new
                {
                    Key = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: false),
                    ResultJson = table.Column<string>(type: "text", nullable: false),
                    FetchedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PackageVulns", x => x.Key);
                });

            migrationBuilder.CreateTable(
                name: "Settings",
                columns: table => new
                {
                    Key = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    Value = table.Column<string>(type: "text", nullable: true),
                    Encrypted = table.Column<bool>(type: "boolean", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Settings", x => x.Key);
                });

            migrationBuilder.CreateTable(
                name: "Suppressions",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Scope = table.Column<int>(type: "integer", nullable: false),
                    CveId = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: true),
                    VendorNorm = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    ProductNorm = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    WatchlistEntryId = table.Column<Guid>(type: "uuid", nullable: true),
                    Reason = table.Column<string>(type: "character varying(1000)", maxLength: 1000, nullable: false),
                    Owner = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    Expiry = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    CreatedBy = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Suppressions", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Tickets",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    VerdictId = table.Column<Guid>(type: "uuid", nullable: false),
                    Channel = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    CorrelationKey = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    ExternalRef = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    SentAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    LastStatus = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Tickets", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Users",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Username = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    Email = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    PasswordHash = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: true),
                    Role = table.Column<int>(type: "integer", nullable: false),
                    Provider = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    LastLoginAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Users", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Watchlist",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Vendor = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    Product = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    VendorNorm = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    ProductNorm = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    Version = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    Cpe = table.Column<string>(type: "character varying(300)", maxLength: 300, nullable: true),
                    AssetName = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: true),
                    Exposure = table.Column<int>(type: "integer", nullable: false),
                    Criticality = table.Column<int>(type: "integer", nullable: false),
                    Note = table.Column<string>(type: "character varying(1000)", maxLength: 1000, nullable: true),
                    Enabled = table.Column<bool>(type: "boolean", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Watchlist", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "WebhookDeliveries",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    At = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    Event = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    VerdictId = table.Column<Guid>(type: "uuid", nullable: false),
                    Url = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: false),
                    StatusCode = table.Column<int>(type: "integer", nullable: true),
                    Error = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_WebhookDeliveries", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "AssetSources",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    AssetId = table.Column<Guid>(type: "uuid", nullable: false),
                    ConnectorId = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    AdapterId = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    ExternalId = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    FirstSeen = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    LastSeen = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AssetSources", x => x.Id);
                    table.ForeignKey(
                        name: "FK_AssetSources_Assets_AssetId",
                        column: x => x.AssetId,
                        principalTable: "Assets",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "Software",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    AssetId = table.Column<Guid>(type: "uuid", nullable: false),
                    Vendor = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    Product = table.Column<string>(type: "character varying(300)", maxLength: 300, nullable: false),
                    Version = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    Edition = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: true),
                    Architecture = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: true),
                    VendorNorm = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    ProductNorm = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    Cpe = table.Column<string>(type: "character varying(300)", maxLength: 300, nullable: true),
                    Purl = table.Column<string>(type: "character varying(400)", maxLength: 400, nullable: true),
                    Ecosystem = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    Kind = table.Column<int>(type: "integer", nullable: false),
                    Enabled = table.Column<bool>(type: "boolean", nullable: false),
                    ListenersJson = table.Column<string>(type: "text", nullable: true),
                    ConnectorId = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    ExternalId = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    FirstSeen = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    LastSeen = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    MappingStatus = table.Column<int>(type: "integer", nullable: false),
                    MappedVendorNorm = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    MappedProductNorm = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Software", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Software_Assets_AssetId",
                        column: x => x.AssetId,
                        principalTable: "Assets",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "CveAffected",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    CveId = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    Vendor = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    Product = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    VendorNorm = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    ProductNorm = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    DefaultStatus = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: true),
                    VersionsJson = table.Column<string>(type: "text", nullable: true),
                    CpesJson = table.Column<string>(type: "text", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CveAffected", x => x.Id);
                    table.ForeignKey(
                        name: "FK_CveAffected_Cves_CveId",
                        column: x => x.CveId,
                        principalTable: "Cves",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "Verdicts",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    CveId = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    WatchlistEntryId = table.Column<Guid>(type: "uuid", nullable: true),
                    SoftwareInstanceId = table.Column<Guid>(type: "uuid", nullable: true),
                    AssetId = table.Column<Guid>(type: "uuid", nullable: true),
                    AppliedModifiersJson = table.Column<string>(type: "text", nullable: true),
                    Subject = table.Column<string>(type: "character varying(400)", maxLength: 400, nullable: false),
                    Exploitation = table.Column<int>(type: "integer", nullable: false),
                    Automatable = table.Column<bool>(type: "boolean", nullable: false),
                    AttackVector = table.Column<int>(type: "integer", nullable: false),
                    DeclaredExposure = table.Column<int>(type: "integer", nullable: false),
                    EffectiveExposure = table.Column<int>(type: "integer", nullable: false),
                    Criticality = table.Column<int>(type: "integer", nullable: false),
                    Epss = table.Column<double>(type: "double precision", nullable: true),
                    InKev = table.Column<bool>(type: "boolean", nullable: false),
                    Tier = table.Column<int>(type: "integer", nullable: false),
                    RuleNumber = table.Column<int>(type: "integer", nullable: false),
                    Confidence = table.Column<int>(type: "integer", nullable: false),
                    SlaDue = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    Sentence = table.Column<string>(type: "character varying(1000)", maxLength: 1000, nullable: false),
                    FixedIn = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    EvidenceJson = table.Column<string>(type: "text", nullable: false),
                    State = table.Column<int>(type: "integer", nullable: false),
                    StateReason = table.Column<string>(type: "character varying(1000)", maxLength: 1000, nullable: true),
                    StateOwner = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: true),
                    StateChangedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    SnoozedUntil = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    AcceptedRiskExpiry = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    SuppressedByRuleId = table.Column<Guid>(type: "uuid", nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    LastEvaluatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    PreviousTier = table.Column<int>(type: "integer", nullable: true),
                    TierChangedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    TierChangeReason = table.Column<string>(type: "character varying(300)", maxLength: 300, nullable: true),
                    ImmediateEmailSentAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    TicketSentAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    FirstDigestAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Verdicts", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Verdicts_Assets_AssetId",
                        column: x => x.AssetId,
                        principalTable: "Assets",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_Verdicts_Cves_CveId",
                        column: x => x.CveId,
                        principalTable: "Cves",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_Verdicts_Software_SoftwareInstanceId",
                        column: x => x.SoftwareInstanceId,
                        principalTable: "Software",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_Verdicts_Watchlist_WatchlistEntryId",
                        column: x => x.WatchlistEntryId,
                        principalTable: "Watchlist",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "VerdictHistory",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    VerdictId = table.Column<Guid>(type: "uuid", nullable: false),
                    At = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    Actor = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    Kind = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    From = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    To = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    Reason = table.Column<string>(type: "character varying(1000)", maxLength: 1000, nullable: true),
                    Digested = table.Column<bool>(type: "boolean", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_VerdictHistory", x => x.Id);
                    table.ForeignKey(
                        name: "FK_VerdictHistory_Verdicts_VerdictId",
                        column: x => x.VerdictId,
                        principalTable: "Verdicts",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_Aliases_AliasNorm",
                table: "Aliases",
                column: "AliasNorm");

            migrationBuilder.CreateIndex(
                name: "IX_Assets_DisplayName",
                table: "Assets",
                column: "DisplayName");

            migrationBuilder.CreateIndex(
                name: "IX_Assets_LastSeen",
                table: "Assets",
                column: "LastSeen");

            migrationBuilder.CreateIndex(
                name: "IX_AssetSources_AssetId",
                table: "AssetSources",
                column: "AssetId");

            migrationBuilder.CreateIndex(
                name: "IX_AssetSources_ConnectorId_ExternalId",
                table: "AssetSources",
                columns: new[] { "ConnectorId", "ExternalId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Audit_At",
                table: "Audit",
                column: "At");

            migrationBuilder.CreateIndex(
                name: "IX_Connectors_AdapterId",
                table: "Connectors",
                column: "AdapterId");

            migrationBuilder.CreateIndex(
                name: "IX_Controls_AssetId",
                table: "Controls",
                column: "AssetId");

            migrationBuilder.CreateIndex(
                name: "IX_Controls_WatchlistEntryId",
                table: "Controls",
                column: "WatchlistEntryId");

            migrationBuilder.CreateIndex(
                name: "IX_CveAffected_CveId",
                table: "CveAffected",
                column: "CveId");

            migrationBuilder.CreateIndex(
                name: "IX_CveAffected_ProductNorm",
                table: "CveAffected",
                column: "ProductNorm");

            migrationBuilder.CreateIndex(
                name: "IX_CveAffected_VendorNorm_ProductNorm",
                table: "CveAffected",
                columns: new[] { "VendorNorm", "ProductNorm" });

            migrationBuilder.CreateIndex(
                name: "IX_Cves_LastModified",
                table: "Cves",
                column: "LastModified");

            migrationBuilder.CreateIndex(
                name: "IX_Cves_Published",
                table: "Cves",
                column: "Published");

            migrationBuilder.CreateIndex(
                name: "IX_DigestRuns_GeneratedAt",
                table: "DigestRuns",
                column: "GeneratedAt");

            migrationBuilder.CreateIndex(
                name: "IX_ExploitSignals_CveId",
                table: "ExploitSignals",
                column: "CveId");

            migrationBuilder.CreateIndex(
                name: "IX_ExploitSignals_CveId_Source_Url",
                table: "ExploitSignals",
                columns: new[] { "CveId", "Source", "Url" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Findings_AssetId",
                table: "Findings",
                column: "AssetId");

            migrationBuilder.CreateIndex(
                name: "IX_Software_AssetId_ConnectorId",
                table: "Software",
                columns: new[] { "AssetId", "ConnectorId" });

            migrationBuilder.CreateIndex(
                name: "IX_Software_MappedVendorNorm_MappedProductNorm",
                table: "Software",
                columns: new[] { "MappedVendorNorm", "MappedProductNorm" });

            migrationBuilder.CreateIndex(
                name: "IX_Software_MappingStatus",
                table: "Software",
                column: "MappingStatus");

            migrationBuilder.CreateIndex(
                name: "IX_Tickets_CorrelationKey",
                table: "Tickets",
                column: "CorrelationKey");

            migrationBuilder.CreateIndex(
                name: "IX_Users_Username",
                table: "Users",
                column: "Username",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_VerdictHistory_VerdictId_At",
                table: "VerdictHistory",
                columns: new[] { "VerdictId", "At" });

            migrationBuilder.CreateIndex(
                name: "IX_Verdicts_AssetId",
                table: "Verdicts",
                column: "AssetId");

            migrationBuilder.CreateIndex(
                name: "IX_Verdicts_CveId_SoftwareInstanceId",
                table: "Verdicts",
                columns: new[] { "CveId", "SoftwareInstanceId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Verdicts_CveId_WatchlistEntryId",
                table: "Verdicts",
                columns: new[] { "CveId", "WatchlistEntryId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Verdicts_SoftwareInstanceId",
                table: "Verdicts",
                column: "SoftwareInstanceId");

            migrationBuilder.CreateIndex(
                name: "IX_Verdicts_State",
                table: "Verdicts",
                column: "State");

            migrationBuilder.CreateIndex(
                name: "IX_Verdicts_Tier",
                table: "Verdicts",
                column: "Tier");

            migrationBuilder.CreateIndex(
                name: "IX_Verdicts_WatchlistEntryId",
                table: "Verdicts",
                column: "WatchlistEntryId");

            migrationBuilder.CreateIndex(
                name: "IX_Watchlist_VendorNorm_ProductNorm",
                table: "Watchlist",
                columns: new[] { "VendorNorm", "ProductNorm" });

            migrationBuilder.CreateIndex(
                name: "IX_WebhookDeliveries_At",
                table: "WebhookDeliveries",
                column: "At");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "Aliases");

            migrationBuilder.DropTable(
                name: "AssetSources");

            migrationBuilder.DropTable(
                name: "Audit");

            migrationBuilder.DropTable(
                name: "Bundles");

            migrationBuilder.DropTable(
                name: "CnaProducts");

            migrationBuilder.DropTable(
                name: "Connectors");

            migrationBuilder.DropTable(
                name: "Controls");

            migrationBuilder.DropTable(
                name: "CveAffected");

            migrationBuilder.DropTable(
                name: "DigestRuns");

            migrationBuilder.DropTable(
                name: "Epss");

            migrationBuilder.DropTable(
                name: "ExploitSignals");

            migrationBuilder.DropTable(
                name: "FeedStatuses");

            migrationBuilder.DropTable(
                name: "Findings");

            migrationBuilder.DropTable(
                name: "Kev");

            migrationBuilder.DropTable(
                name: "Narratives");

            migrationBuilder.DropTable(
                name: "PackageVulns");

            migrationBuilder.DropTable(
                name: "Settings");

            migrationBuilder.DropTable(
                name: "Suppressions");

            migrationBuilder.DropTable(
                name: "Tickets");

            migrationBuilder.DropTable(
                name: "Users");

            migrationBuilder.DropTable(
                name: "VerdictHistory");

            migrationBuilder.DropTable(
                name: "WebhookDeliveries");

            migrationBuilder.DropTable(
                name: "Verdicts");

            migrationBuilder.DropTable(
                name: "Cves");

            migrationBuilder.DropTable(
                name: "Software");

            migrationBuilder.DropTable(
                name: "Watchlist");

            migrationBuilder.DropTable(
                name: "Assets");
        }
    }
}
