using System;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace VulnVerdict.Core.Data.Migrations.Postgres
{
    /// <inheritdoc />
    public partial class Advisories : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "Advisories",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    Vendor = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    AdvisoryId = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    Title = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    Url = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    Published = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    Updated = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    CveIdsJson = table.Column<string>(type: "text", nullable: false),
                    AffectedJson = table.Column<string>(type: "text", nullable: true),
                    Severity = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: true),
                    ExploitedInTheWild = table.Column<bool>(type: "boolean", nullable: false),
                    RetrievedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Advisories", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_Advisories_Updated",
                table: "Advisories",
                column: "Updated");

            migrationBuilder.CreateIndex(
                name: "IX_Advisories_Vendor_AdvisoryId",
                table: "Advisories",
                columns: new[] { "Vendor", "AdvisoryId" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "Advisories");
        }
    }
}
