using JwtAuthNet8.Entities;
using Microsoft.EntityFrameworkCore;

namespace JwtAuthNet8.Data
{
    public class UserDbContext(DbContextOptions<UserDbContext> options) : DbContext(options)
    {
        public DbSet<User> users { get; set; }
    }
}
