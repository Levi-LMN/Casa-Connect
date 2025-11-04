// Program.cs
// Purpose: Application startup and security configuration
// OWASP Top 10 Security Implementations:
// - A01:2021 Broken Access Control: Authorization policies, role-based access control
// - A02:2021 Cryptographic Failures: HTTPS redirection, data protection, HSTS
// - A04:2021 Insecure Design: Account lockout, strong password policies
// - A05:2021 Security Misconfiguration: Secure defaults, production hardening
// - A06:2021 Vulnerable and Outdated Components: Latest ASP.NET Core Identity
// - A07:2021 Identification and Authentication Failures: Password requirements, lockout protection
// - A09:2021 Security Logging and Monitoring: Serilog structured logging

using CasaConnect.Data;
using CasaConnect.Models;
using DotNetEnv; // For loading .env file
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Serilog;

namespace CasaConnect
{
    public class Program
    {
        public static async Task Main(string[] args)
        {
            // OWASP A05: Load environment variables from .env (local development only)
            Env.Load();

            var builder = WebApplication.CreateBuilder(args);

            // OWASP A09: Configure structured logging with Serilog
            // Provides audit trail for security events
            Log.Logger = new LoggerConfiguration()
                .ReadFrom.Configuration(builder.Configuration)
                .Enrich.FromLogContext()
                .CreateLogger();

            builder.Host.UseSerilog();

            // Add MVC services
            builder.Services.AddControllersWithViews();

            // OWASP A03: Configure database context with SQLite
            // EF Core provides parameterized queries by default (SQL injection protection)
            builder.Services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection")));

            // OWASP A02: Configure HTTPS redirection
            // Forces all HTTP requests to use HTTPS (protects data in transit)
            builder.Services.AddHttpsRedirection(options =>
            {
                options.RedirectStatusCode = StatusCodes.Status308PermanentRedirect;
                options.HttpsPort = 5001; // Development HTTPS port
            });

            // OWASP A02, A06, A07: Identity configuration
            // Uses latest ASP.NET Core Identity with secure defaults
            builder.Services.AddIdentity<User, ApplicationRole>(options =>
            {
                // OWASP A07: Strong password policy requirements
                options.Password.RequireDigit = true;
                options.Password.RequiredLength = 8;
                options.Password.RequireLowercase = true;
                options.Password.RequireUppercase = true;
                options.Password.RequireNonAlphanumeric = true;

                // OWASP A04 & A07: Account lockout protection against brute force attacks
                options.Lockout.MaxFailedAccessAttempts = 5;
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
            })
            .AddEntityFrameworkStores<ApplicationDbContext>()
            .AddDefaultTokenProviders(); // OWASP A07: Token providers for password reset, 2FA

            // OWASP A01: Authorization policies for role-based access control
            builder.Services.AddAuthorization(options =>
            {
                options.AddPolicy("AdminOnly", policy => policy.RequireRole("Admin"));
            });

            // OWASP A05: IHttpClientFactory for secure HTTP client management
            builder.Services.AddHttpClient();

            // OWASP A02: Data protection API for encrypting sensitive data
            // Used by Identity for tokens, cookies, etc.
            builder.Services.AddDataProtection();

            // SignalR for real-time messaging
            builder.Services.AddSignalR();

            var app = builder.Build();

            // OWASP A05: Initialize database (seed roles and admin user)
            using (var scope = app.Services.CreateScope())
            {
                var services = scope.ServiceProvider;
                var context = services.GetRequiredService<ApplicationDbContext>();
                var userManager = services.GetRequiredService<UserManager<User>>();
                var roleManager = services.GetRequiredService<RoleManager<ApplicationRole>>();
                await DbInitializer.Initialize(context, userManager, roleManager);
            }

            // OWASP A05: Configure middleware pipeline
            if (!app.Environment.IsDevelopment())
            {
                // OWASP A04: Use generic error handler in production (don't expose stack traces)
                app.UseExceptionHandler("/Home/Error");

                // OWASP A02: Enable HSTS only in production
                // HTTP Strict Transport Security - forces browsers to use HTTPS
                app.UseHsts();
            }

            // OWASP A02: Always redirect HTTP to HTTPS
            // Ensures all communication is encrypted
            app.UseHttpsRedirection();

            // Serve static files (CSS, JS, images)
            app.UseStaticFiles();

            app.UseRouting();

            // OWASP A07: Authentication middleware - validates user identity
            app.UseAuthentication();

            // OWASP A01: Authorization middleware - enforces access control policies
            app.UseAuthorization();

            // Map MVC controllers with default route
            app.MapControllerRoute(
                name: "default",
                pattern: "{controller=Home}/{action=Index}/{id?}");

            // Map SignalR hub for real-time messaging
            app.MapHub<MessageHub>("/messageHub");

            await app.RunAsync();
        }
    }
}