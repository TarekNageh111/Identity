using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace JWT_Backend.Migrations
{
    public partial class AddNewSeedingRoles : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.InsertData
                (
                table: "AspNetRoles",
                columns: new[] { "Id", "Name", "NormalizedName", "ConcurrencyStamp" },
                values: new object[] { Guid.NewGuid().ToString(), "Manager", "Manager".ToUpper(), Guid.NewGuid().ToString() }
                );    
            migrationBuilder.InsertData
                (
                table: "AspNetRoles",
                columns: new[] { "Id", "Name", "NormalizedName", "ConcurrencyStamp" },
                values: new object[] { Guid.NewGuid().ToString(), "Viewer", "Viewer".ToUpper(), Guid.NewGuid().ToString() }
                );
            migrationBuilder.InsertData
     (
     table: "AspNetRoles",
     columns: new[] { "Id", "Name", "NormalizedName", "ConcurrencyStamp" },
     values: new object[] { Guid.NewGuid().ToString(), "Shower", "Shower".ToUpper(), Guid.NewGuid().ToString() }
     );
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("delete from AspNetRoles");
        }
    }
}
