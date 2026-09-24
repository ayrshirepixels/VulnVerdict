using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace VulnVerdict.Core.Data.Migrations.Sqlite
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
                    Id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    Vendor = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false),
                    AdvisoryId = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    Title = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    Url = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    Published = table.Column<DateTime>(type: "TEXT", nullable: true),
                    Updated = table.Column<DateTime>(type: "TEXT", nullable: true),
                    CveIdsJson = table.Column<string>(type: "TEXT", nullable: false),
                    AffectedJson = table.Column<string>(type: "TEXT", nullable: true),
                    Severity = table.Column<string>(type: "TEXT", maxLength: 32, nullable: true),
                    ExploitedInTheWild = table.Column<bool>(type: "INTEGER", nullable: false),
                    RetrievedAt = table.Column<DateTime>(type: "TEXT", nullable: false)
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
