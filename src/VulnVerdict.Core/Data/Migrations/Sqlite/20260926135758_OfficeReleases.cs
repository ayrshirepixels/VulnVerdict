using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace VulnVerdict.Core.Data.Migrations.Sqlite
{
    /// <inheritdoc />
    public partial class OfficeReleases : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "OfficeReleases",
                columns: table => new
                {
                    Id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    Channel = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    Version = table.Column<string>(type: "TEXT", maxLength: 8, nullable: false),
                    Build = table.Column<int>(type: "INTEGER", nullable: false),
                    Revision = table.Column<int>(type: "INTEGER", nullable: false),
                    Released = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_OfficeReleases", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_OfficeReleases_Build_Released",
                table: "OfficeReleases",
                columns: new[] { "Build", "Released" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "OfficeReleases");
        }
    }
}
