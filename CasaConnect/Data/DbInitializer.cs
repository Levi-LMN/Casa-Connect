using CasaConnect.Data;
using CasaConnect.Models;
using Microsoft.AspNetCore.Identity;

public static class DbInitializer
{
    public static void Initialize(ApplicationDbContext context, IPasswordHasher<User> passwordHasher)
    {
        context.Database.EnsureCreated();

        // Check if we already have any users
        if (context.Users.Any())
        {
            return;   // DB has been seeded
        }

        var adminUser = new User
        {
            FirstName = "Admin",
            LastName = "User",
            Email = "admin@casaconnect.com",
            Password = HashPassword(passwordHasher, "Admin@123"),
            Role = "Admin",
            PhoneNo = "1234567890",
            Address = "Admin Address",
            IsActive = true,
            CreatedAt = DateTime.UtcNow
        };

        context.Users.Add(adminUser);
        context.SaveChanges();
    }

    private static string HashPassword(IPasswordHasher<User> passwordHasher, string password)
    {
        var user = new User(); // Dummy user object for hashing
        return passwordHasher.HashPassword(user, password);
    }
}
