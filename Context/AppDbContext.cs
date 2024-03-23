using Identity.Configurations;
using Identity.Entities;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Identity.Context;

public class AppDbContext(DbContextOptions options) : IdentityDbContext<User>(options)
{
    protected override void OnModelCreating(ModelBuilder builder)
    {
        builder.Seed();
        base.OnModelCreating(builder);
    }
}
