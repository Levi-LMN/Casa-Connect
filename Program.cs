using CasaConnect.Data;
using CasaConnect.Models;
using DotNetEnv; //  For loading .env file
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Serilog;

namespace CasaConnect
{
    public class Program
    {
        public static async Task Main(string[] args)
        {
            // Load .env file (only in local dev)
            Env.Load();

            var builder = WebApplication.CreateBuilder(args);

            // Configure logging (Serilog)
            Log.Logger = new LoggerConfiguration()
                .ReadFrom.Configuration(builder.Configuration)
                .Enrich.FromLogContext()
                .CreateLogger();

            builder.Host.UseSerilog();

            //  Add services
            builder.Services.AddControllersWithViews();

            // Configure database context to use SQLite (connection from .env)
            builder.Services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection")));

            //  Configure HTTPS redirection
            builder.Services.AddHttpsRedirection(options =>
            {
                options.RedirectStatusCode = StatusCodes.Status308PermanentRedirect;
                options.HttpsPort = 5001; // Use dev HTTPS port
            });

            //  Identity configuration
            // Uses PBKDF2 algorithm (100,000 iterations in .NET 6+)
            builder.Services.AddIdentity<User, ApplicationRole>(options =>
            {
                options.Password.RequireDigit = true;
                options.Password.RequiredLength = 8;
                options.Password.RequireLowercase = true;
                options.Password.RequireUppercase = true;
                options.Password.RequireNonAlphanumeric = true;
                options.Lockout.MaxFailedAccessAttempts = 5;
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
            })
            .AddEntityFrameworkStores<ApplicationDbContext>()
            .AddDefaultTokenProviders();

            //  Authorization policies
            builder.Services.AddAuthorization(options =>
            {
                options.AddPolicy("AdminOnly", policy => policy.RequireRole("Admin"));
            });

            //  IHttpClientFactory
            builder.Services.AddHttpClient();

            //  Data protection
            builder.Services.AddDataProtection();

            //  SignalR
            builder.Services.AddSignalR();

            var app = builder.Build();

            //  Initialize the database (seed roles and admin)
            using (var scope = app.Services.CreateScope())
            {
                var services = scope.ServiceProvider;
                var context = services.GetRequiredService<ApplicationDbContext>();
                var userManager = services.GetRequiredService<UserManager<User>>();
                var roleManager = services.GetRequiredService<RoleManager<ApplicationRole>>();
                await DbInitializer.Initialize(context, userManager, roleManager);
            }

            //  Configure middleware pipeline
            if (!app.Environment.IsDevelopment())
            {
                app.UseExceptionHandler("/Home/Error");
                app.UseHsts(); // Enable HSTS only in production
            }

            //  Always redirect HTTP -> HTTPS
            app.UseHttpsRedirection();

            app.UseStaticFiles();
            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();

            //  Map controllers and hubs
            app.MapControllerRoute(
                name: "default",
                pattern: "{controller=Home}/{action=Index}/{id?}");

            app.MapHub<MessageHub>("/messageHub");

            await app.RunAsync();
        }
    }
}
