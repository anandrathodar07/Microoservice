using Login.Model;

using Microsoft.AspNetCore.Identity;

using Microsoft.EntityFrameworkCore;
using System.Collections.Generic;

namespace Login.ApplictionDbContext
{


    public class AppDbContext : Microsoft.AspNetCore.Identity.EntityFrameworkCore.IdentityDbContext<IdentityUser, IdentityRole, string>
    {
        public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();

        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            builder.Entity<RefreshToken>(e =>
            {
                e.HasIndex(x => x.Token).IsUnique();
                e.Property(x => x.Token).IsRequired();
            });
        }
    }
}
