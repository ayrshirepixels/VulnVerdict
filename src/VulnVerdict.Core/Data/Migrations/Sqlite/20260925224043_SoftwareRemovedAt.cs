using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace VulnVerdict.Core.Data.Migrations.Sqlite
{
    /// <inheritdoc />
    public partial class SoftwareRemovedAt : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTime>(
                name: "RemovedAt",
                table: "Software",
                type: "TEXT",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "RemovedAt",
                table: "Software");
        }
    }
}
