using Identity.Configurations;
using Identity.Entities;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Identity.Context;

public class AppDbContext : IdentityDbContext<User>
{
    public AppDbContext(DbContextOptions options) : base(options) => Database.EnsureCreated();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        builder.Seed();
        base.OnModelCreating(builder);
    }
}
