using System;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace VulnVerdict.Core.Data.Migrations.Postgres
{
    /// <inheritdoc />
    public partial class Operations : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "FailedPasswordCount",
                table: "Users",
                type: "integer",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<int>(
                name: "FailedSecondFactorCount",
                table: "Users",
                type: "integer",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<DateTime>(
                name: "PasswordLockedUntil",
                table: "Users",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "RecoveryCodeHashes",
                table: "Users",
                type: "character varying(2000)",
                maxLength: 2000,
                nullable: true);

            migrationBuilder.AddColumn<DateTime>(
                name: "SecondFactorLockedUntil",
                table: "Users",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<DateTime>(
                name: "TotpEnabledAt",
                table: "Users",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<long>(
                name: "TotpLastStep",
                table: "Users",
                type: "bigint",
                nullable: false,
                defaultValue: 0L);

            migrationBuilder.AddColumn<string>(
                name: "TotpSecret",
                table: "Users",
                type: "character varying(512)",
                maxLength: 512,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "PendingHostKeysJson",
                table: "Connectors",
                type: "text",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "EolCycles",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    Slug = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    ProductLabel = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    Aliases = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    Cycle = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    CycleLabel = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    ReleaseDate = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    IsEol = table.Column<bool>(type: "boolean", nullable: false),
                    EolFrom = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    EoasFrom = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    EoesFrom = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    IsMaintained = table.Column<bool>(type: "boolean", nullable: false),
                    Latest = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    Link = table.Column<string>(type: "character varying(300)", maxLength: 300, nullable: true),
                    RetrievedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_EolCycles", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "MetricCounters",
                columns: table => new
                {
                    Name = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    Label = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    Value = table.Column<long>(type: "bigint", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_MetricCounters", x => new { x.Name, x.Label });
                });

            migrationBuilder.CreateTable(
                name: "Outbox",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    Kind = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    Event = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    VerdictId = table.Column<Guid>(type: "uuid", nullable: true),
                    PayloadJson = table.Column<string>(type: "text", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    Attempts = table.Column<int>(type: "integer", nullable: false),
                    NextAttemptAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    LastError = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    DeliveredAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    FailedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Outbox", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "SlaSnapshots",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    Day = table.Column<DateOnly>(type: "date", nullable: false),
                    Tier = table.Column<int>(type: "integer", nullable: false),
                    Open = table.Column<int>(type: "integer", nullable: false),
                    Overdue = table.Column<int>(type: "integer", nullable: false),
                    Snoozed = table.Column<int>(type: "integer", nullable: false),
                    AcceptedRisk = table.Column<int>(type: "integer", nullable: false),
                    Backfilled = table.Column<bool>(type: "boolean", nullable: false),
                    RecordedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SlaSnapshots", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "VexDocuments",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    Provider = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    Path = table.Column<string>(type: "character varying(400)", maxLength: 400, nullable: false),
                    CveId = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: true),
                    DocumentId = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: true),
                    ChangedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    FetchedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    Scope = table.Column<string>(type: "text", nullable: false),
                    Statements = table.Column<int>(type: "integer", nullable: false),
                    Attempts = table.Column<int>(type: "integer", nullable: false),
                    LastError = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_VexDocuments", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "VexStatements",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    Provider = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    DocumentId = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    CveId = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    Status = table.Column<int>(type: "integer", nullable: false),
                    Vendor = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    Product = table.Column<string>(type: "character varying(300)", maxLength: 300, nullable: false),
                    VendorNorm = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    ProductNorm = table.Column<string>(type: "character varying(300)", maxLength: 300, nullable: false),
                    Version = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: true),
                    VersionRange = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    Platform = table.Column<string>(type: "character varying(300)", maxLength: 300, nullable: true),
                    PlatformNorm = table.Column<string>(type: "character varying(300)", maxLength: 300, nullable: true),
                    PlatformCpe = table.Column<string>(type: "character varying(300)", maxLength: 300, nullable: true),
                    Cpe = table.Column<string>(type: "character varying(300)", maxLength: 300, nullable: true),
                    Purl = table.Column<string>(type: "character varying(400)", maxLength: 400, nullable: true),
                    Justification = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    Detail = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    Url = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    DocumentDate = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    Revision = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: true),
                    RetrievedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_VexStatements", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_EolCycles_Slug_Cycle",
                table: "EolCycles",
                columns: new[] { "Slug", "Cycle" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Outbox_NextAttemptAt",
                table: "Outbox",
                column: "NextAttemptAt");

            migrationBuilder.CreateIndex(
                name: "IX_SlaSnapshots_Day_Tier",
                table: "SlaSnapshots",
                columns: new[] { "Day", "Tier" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_VexDocuments_Provider_Path",
                table: "VexDocuments",
                columns: new[] { "Provider", "Path" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_VexStatements_CveId",
                table: "VexStatements",
                column: "CveId");

            migrationBuilder.CreateIndex(
                name: "IX_VexStatements_Provider_DocumentId",
                table: "VexStatements",
                columns: new[] { "Provider", "DocumentId" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "EolCycles");

            migrationBuilder.DropTable(
                name: "MetricCounters");

            migrationBuilder.DropTable(
                name: "Outbox");

            migrationBuilder.DropTable(
                name: "SlaSnapshots");

            migrationBuilder.DropTable(
                name: "VexDocuments");

            migrationBuilder.DropTable(
                name: "VexStatements");

            migrationBuilder.DropColumn(
                name: "FailedPasswordCount",
                table: "Users");

            migrationBuilder.DropColumn(
                name: "FailedSecondFactorCount",
                table: "Users");

            migrationBuilder.DropColumn(
                name: "PasswordLockedUntil",
                table: "Users");

            migrationBuilder.DropColumn(
                name: "RecoveryCodeHashes",
                table: "Users");

            migrationBuilder.DropColumn(
                name: "SecondFactorLockedUntil",
                table: "Users");

            migrationBuilder.DropColumn(
                name: "TotpEnabledAt",
                table: "Users");

            migrationBuilder.DropColumn(
                name: "TotpLastStep",
                table: "Users");

            migrationBuilder.DropColumn(
                name: "TotpSecret",
                table: "Users");

            migrationBuilder.DropColumn(
                name: "PendingHostKeysJson",
                table: "Connectors");
        }
    }
}
