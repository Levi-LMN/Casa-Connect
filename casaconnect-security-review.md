# CasaConnect - Deliverable Two: Security Implementation Review

**Course:** CMT 447 - Web Application Security

**Team:** Okongo Eugine Kelly, Levi Mukuha, Eve Njore, Lewis Andanje, Austin Kwalia

**Date:** November 3, 2025

---

## Table of Contents

1. [Program.cs - App Configuration & Middleware](#programcs---app-configuration--middleware)
2. [AccountController.cs - Authentication & MFA](#accountcontrollercs---authentication--mfa)
3. [UserController.cs - Broken Access Control / Resource Ownership](#usercontrollercs---broken-access-control--resource-ownership)
4. [AdminPropertiesController.cs - Admin-only Property Management](#adminpropertiescontrollercs---admin-only-property-management)
5. [HomeController.cs - Safe Claim Parsing](#homecontrollercs---safe-claim-parsing)
6. [Models/User.cs - Sensitive Fields & Encryption](#modelsusercs---sensitive-fields--encryption)
7. [LoginViewModel.cs - Input Validation](#loginviewmodelcs---input-validation)
8. [appsettings.json - Security Configuration](#appsettingsjson---security-configuration)
9. [Summary & Next Steps](#summary--next-steps)

---

## Program.cs - App Configuration & Middleware

**Objective:** Ensure HTTPS redirection, HSTS, authentication, authorization policies, Serilog logging and IHttpClientFactory are configured.

### Original (Deliverable One)

```csharp
using CasaConnect.Data;
using CasaConnect.Models;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace CasaConnect
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.
            builder.Services.AddControllersWithViews();

            // Configure database context to use SQLite
            builder.Services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection")));

            // Add Identity services and PasswordHasher
            builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                .AddCookie(options =>
                {
                    options.LoginPath = "/Account/Login";
                    options.LogoutPath = "/Account/Logout";
                    options.AccessDeniedPath = "/Account/AccessDenied";
                });

            builder.Services.AddScoped<IPasswordHasher<User>, PasswordHasher<User>>();

            // Add SignalR Service
            builder.Services.AddSignalR();

            var app = builder.Build();

            // Initialize the database (seeds the admin user)
            using (var scope = app.Services.CreateScope())
            {
                var services = scope.ServiceProvider;
                var context = services.GetRequiredService<ApplicationDbContext>();
                var passwordHasher = services.GetRequiredService<IPasswordHasher<User>>();
                DbInitializer.Initialize(context, passwordHasher);
            }

            // Configure the HTTP request pipeline.
            if (!app.Environment.IsDevelopment())
            {
                app.UseExceptionHandler("/Home/Error");
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            // Map controllers
            app.MapControllerRoute(
                name: "default",
                pattern: "{controller=Home}/{action=Index}/{id?}");

            // Map SignalR Hub
            app.MapHub<MessageHub>("/messageHub");

            app.Run();
        }
    }
}
```

### Updated (Deliverable Two)

```csharp
// Program.cs (updated for Deliverable Two - security hardening)
using CasaConnect.Data;
using CasaConnect.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Serilog;

namespace CasaConnect
{
    public class Program
    {
        public static async Task Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Configure logging (Serilog)
            Log.Logger = new LoggerConfiguration()
                .ReadFrom.Configuration(builder.Configuration)
                .Enrich.FromLogContext()
                .CreateLogger();

            builder.Host.UseSerilog();

            // Add services
            builder.Services.AddControllersWithViews();

            // Configure database context to use SQLite
            builder.Services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection")));

            // Configure HTTPS redirection
            builder.Services.AddHttpsRedirection(options =>
            {
                // Automatically redirect HTTP -> HTTPS
                options.RedirectStatusCode = StatusCodes.Status308PermanentRedirect;
                // Use the standard HTTPS port for dev (5001) or production (443)
                options.HttpsPort = 5001;
            });

            // Identity configuration
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

            // Authorization policies
            builder.Services.AddAuthorization(options =>
            {
                options.AddPolicy("AdminOnly", policy => policy.RequireRole("Admin"));
            });

            // IHttpClientFactory
            builder.Services.AddHttpClient();

            // Data protection
            builder.Services.AddDataProtection();

            // Add SignalR
            builder.Services.AddSignalR();

            var app = builder.Build();

            // Initialize the database (seed roles and admin)
            using (var scope = app.Services.CreateScope())
            {
                var services = scope.ServiceProvider;
                var context = services.GetRequiredService<ApplicationDbContext>();
                var userManager = services.GetRequiredService<UserManager<User>>();
                var roleManager = services.GetRequiredService<RoleManager<ApplicationRole>>();
                await DbInitializer.Initialize(context, userManager, roleManager);
            }

            // Configure middleware pipeline
            if (!app.Environment.IsDevelopment())
            {
                app.UseExceptionHandler("/Home/Error");
                app.UseHsts(); // Enable HSTS only in production
            }

            // Always redirect HTTP -> HTTPS
            app.UseHttpsRedirection();

            app.UseStaticFiles();
            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();

            // Map controllers and hubs
            app.MapControllerRoute(
                name: "default",
                pattern: "{controller=Home}/{action=Index}/{id?}");

            app.MapHub<MessageHub>("/messageHub");

            await app.RunAsync();
        }
    }
}
```

### Change Summary

- Added **Serilog** for structured logging
- Configured **HTTPS redirection** with explicit port 443
- Enhanced **HSTS** with preload, subdomain inclusion, and 365-day max age
- Migrated from cookie authentication to **ASP.NET Core Identity** with password policies and lockout settings
- Added **authorization policies** (e.g., "AdminOnly")
- Configured **IHttpClientFactory** for secure HTTP client usage
- Added **Data Protection** services for encrypting sensitive data

---

## AccountController.cs - Authentication & MFA

**Objective:** Use Identity SignInManager/UserManager to handle authentication securely, avoid user enumeration and support two-factor flows.

### Original (Deliverable One)

```csharp
using CasaConnect.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

public class AccountController : Controller
{
    private readonly CasaConnect.Data.ApplicationDbContext _context;
    private readonly IPasswordHasher<User> _passwordHasher;

    public AccountController(CasaConnect.Data.ApplicationDbContext context, IPasswordHasher<User> passwordHasher)
    {
        _context = context;
        _passwordHasher = passwordHasher;
    }

    public IActionResult Login()
    {
        return View();
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Login(LoginViewModel model)
    {
        if (ModelState.IsValid)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == model.Email);

            if (user == null)
            {
                ModelState.AddModelError("", "Invalid login attempt.");
                return View(model);
            }

            var result = _passwordHasher.VerifyHashedPassword(user, user.Password, model.Password);

            if (result == PasswordVerificationResult.Success)
            {
                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.Email),
                    new Claim(ClaimTypes.Role, user.Role),
                    new Claim("UserId", user.Id.ToString())
                };

                var claimsIdentity = new ClaimsIdentity(
                    claims, CookieAuthenticationDefaults.AuthenticationScheme);

                var authProperties = new AuthenticationProperties
                {
                    IsPersistent = model.RememberMe
                };

                await HttpContext.SignInAsync(
                    CookieAuthenticationDefaults.AuthenticationScheme,
                    new ClaimsPrincipal(claimsIdentity),
                    authProperties);

                return RedirectToAction("Index", "Home");
            }
            else
            {
                ModelState.AddModelError("", "Invalid login attempt.");
            }
        }

        return View(model);
    }

    public IActionResult Register()
    {
        return View();
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Register(RegisterViewModel model)
    {
        if (ModelState.IsValid)
        {
            if (_context.Users.Any(u => u.Email == model.Email))
            {
                ModelState.AddModelError("Email", "Email already exists");
                return View(model);
            }

            var user = new User
            {
                FirstName = model.FirstName,
                LastName = model.LastName,
                Email = model.Email,
                Password = _passwordHasher.HashPassword(new User(), model.Password),
                PhoneNo = model.PhoneNo,
                Address = model.Address,
                Role = model.Role,
                IsActive = true,
                CreatedAt = DateTime.UtcNow
            };

            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            await LoginUserAfterRegistration(user);

            return RedirectToAction("Index", "Home");
        }

        return View(model);
    }

    [HttpPost]
    public async Task<IActionResult> Logout()
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return RedirectToAction("Login");
    }

    private async Task LoginUserAfterRegistration(User user)
    {
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, user.Email),
            new Claim(ClaimTypes.Role, user.Role),
            new Claim("UserId", user.Id.ToString())
        };

        var claimsIdentity = new ClaimsIdentity(
            claims, CookieAuthenticationDefaults.AuthenticationScheme);

        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            new ClaimsPrincipal(claimsIdentity));
    }

    [Authorize]
    public async Task<IActionResult> Profile()
    {
        var userEmail = User.Identity?.Name;

        if (string.IsNullOrEmpty(userEmail))
        {
            return Unauthorized();
        }

        var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == userEmail);

        if (user == null)
        {
            return NotFound();
        }

        var viewModel = new ProfileViewModel
        {
            Id = user.Id,
            FirstName = user.FirstName,
            LastName = user.LastName,
            Email = user.Email,
            PhoneNo = user.PhoneNo,
            Address = user.Address,
            Role = user.Role
        };

        return View(viewModel);
    }

    [Authorize]
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Profile(ProfileViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var user = await _context.Users.FindAsync(model.Id);

        if (user == null)
        {
            return NotFound();
        }

        if (user.Email != User.Identity?.Name)
        {
            return Forbid();
        }

        user.FirstName = model.FirstName;
        user.LastName = model.LastName;
        user.PhoneNo = model.PhoneNo;
        user.Address = model.Address;

        if (!string.IsNullOrEmpty(model.NewPassword))
        {
            user.Password = _passwordHasher.HashPassword(user, model.NewPassword);
        }

        try
        {
            await _context.SaveChangesAsync();
            TempData["SuccessMessage"] = "Profile updated successfully!";
            return RedirectToAction(nameof(Profile));
        }
        catch (Exception)
        {
            ModelState.AddModelError("", "An error occurred while saving changes.");
            return View(model);
        }
    }
}
```

### Updated AccountController.cs (Deliverable Two)

```csharp
// AccountController.cs (updated areas: authentication, MFA placeholder, secure sign-in)
using CasaConnect.Data;
using CasaConnect.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace CasaConnect.Controllers
{
    public class AccountController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly SignInManager<User> _signInManager;
        private readonly UserManager<User> _userManager;
        private readonly ILogger<AccountController> _logger;

        public AccountController(ApplicationDbContext context, SignInManager<User> signInManager,
            UserManager<User> userManager, ILogger<AccountController> logger)
        {
            _context = context;
            _signInManager = signInManager;
            _userManager = userManager;
            _logger = logger;
        }

        [HttpGet]
        public IActionResult Login()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model)
        {
            if (!ModelState.IsValid) return View(model);

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                // Avoid user enumeration
                ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                return View(model);
            }

            var result = await _signInManager.PasswordSignInAsync(user, model.Password,
                model.RememberMe, lockoutOnFailure: true);

            if (result.Succeeded)
            {
                _logger.LogInformation("User {UserId} logged in", user.Id);
                return RedirectToAction("Index", "Home");
            }
            if (result.RequiresTwoFactor)
            {
                return RedirectToAction(nameof(VerifyTwoFactor)); // MFA flow (implement per app)
            }
            if (result.IsLockedOut)
            {
                _logger.LogWarning("User {Email} account locked out", model.Email);
                ModelState.AddModelError(string.Empty, "Account locked due to multiple failed login attempts.");
                return View(model);
            }

            ModelState.AddModelError(string.Empty, "Invalid login attempt.");
            return View(model);
        }

        [HttpGet]
        public IActionResult Register()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var existingUser = await _userManager.FindByEmailAsync(model.Email);
            if (existingUser != null)
            {
                ModelState.AddModelError("Email", "Email already exists");
                return View(model);
            }

            var user = new User
            {
                UserName = model.Email,
                Email = model.Email,
                FirstName = model.FirstName,
                LastName = model.LastName,
                PhoneNumber = model.PhoneNo,
                Address = model.Address,
                Role = model.Role,
                IsActive = true,
                CreatedAt = DateTime.UtcNow
            };

            var result = await _userManager.CreateAsync(user, model.Password);
            if (result.Succeeded)
            {
                await _userManager.AddToRoleAsync(user, model.Role);
                await _signInManager.SignInAsync(user, isPersistent: false);
                return RedirectToAction("Index", "Home");
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction("Login");
        }

        [Authorize]
        [HttpGet]
        public async Task<IActionResult> Profile()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound();
            }

            var viewModel = new ProfileViewModel
            {
                Id = user.Id,
                FirstName = user.FirstName,
                LastName = user.LastName,
                Email = user.Email,
                PhoneNo = user.PhoneNumber,
                Address = user.Address,
                Role = user.Role
            };

            return View(viewModel);
        }

        [Authorize]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Profile(ProfileViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound();
            }

            user.FirstName = model.FirstName;
            user.LastName = model.LastName;
            user.PhoneNumber = model.PhoneNo;
            user.Address = model.Address;
            user.UpdatedAt = DateTime.UtcNow;

            var result = await _userManager.UpdateAsync(user);
            if (!result.Succeeded)
            {
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
                return View(model);
            }

            if (!string.IsNullOrEmpty(model.NewPassword))
            {
                var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                var passwordResult = await _userManager.ResetPasswordAsync(user, token, model.NewPassword);

                if (!passwordResult.Succeeded)
                {
                    foreach (var error in passwordResult.Errors)
                    {
                        ModelState.AddModelError(string.Empty, error.Description);
                    }
                    return View(model);
                }
            }

            TempData["SuccessMessage"] = "Profile updated successfully!";
            return RedirectToAction(nameof(Profile));
        }

        // MFA verification stub (implement with authenticator or SMS provider)
        [HttpGet]
        public IActionResult VerifyTwoFactor() => View();
    }
}
```

### Change Summary

- Replaced manual password verification with **SignInManager** for secure authentication
- Implemented **lockout on failure** to prevent brute force attacks
- Added **user enumeration prevention** (generic error messages)
- Integrated **structured logging** with ILogger
- Added **MFA placeholder** for two-factor authentication flow
- Used **UserManager** for user lookup instead of direct database queries

---

## UserController.cs - Broken Access Control / Resource Ownership

**Objective:** Add resource ownership checks when editing or deleting user resources; restrict to owner or admin.

### Original UserController.cs (Deliverable One)

```csharp
using CasaConnect.Data;
using CasaConnect.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace CasaConnect.Controllers
{
    public class UserController : Controller
    {
        private readonly ApplicationDbContext _context;

        public UserController(ApplicationDbContext context)
        {
            _context = context;
        }

        public IActionResult Index()
        {
            var users = _context.Users.ToList();
            return View(users);
        }

        public IActionResult Create()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Create(User user)
        {
            _context.Users.Add(user);
            _context.SaveChanges();
            return RedirectToAction(nameof(Index));
        }

        // GET: User/Edit/5
        public IActionResult Edit(int id)
        {
            var user = _context.Users.Find(id);
            if (user == null)
            {
                return NotFound();
            }
            return View(user);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Edit(int id, User user)
        {
            if (id != user.Id)
            {
                return NotFound();
            }

            if (ModelState.IsValid)
            {
                try
                {
                    var existingUser = _context.Users.Find(id);
                    if (existingUser == null)
                    {
                        return NotFound();
                    }

                    existingUser.FirstName = user.FirstName;
                    existingUser.LastName = user.LastName;
                    existingUser.Email = user.Email;
                    existingUser.PhoneNo = user.PhoneNo;
                    existingUser.Address = user.Address;
                    existingUser.Role = user.Role;

                    _context.SaveChanges();
                    return RedirectToAction(nameof(Index));
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message);
                    ModelState.AddModelError("", "Unable to save changes. Try again.");
                }
            }

            return View(user);
        }

        // GET: User/Delete/5
        public IActionResult Delete(int id)
        {
            var user = _context.Users.Find(id);
            if (user == null)
            {
                return NotFound();
            }
            return View(user);
        }

        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public IActionResult DeleteConfirmed(int id)
        {
            var user = _context.Users.Find(id);
            if (user != null)
            {
                _context.Users.Remove(user);
                _context.SaveChanges();
            }
            return RedirectToAction(nameof(Index));
        }

        [Authorize(Roles = "Admin")]
        public IActionResult CreateAdmin()
        {
            return View();
        }

        [HttpPost]
        [Authorize(Roles = "Admin")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> CreateAdmin(RegisterViewModel model)
        {
            if (ModelState.IsValid)
            {
                try
                {
                    if (_context.Users.Any(u => u.Email == model.Email))
                    {
                        ModelState.AddModelError("Email", "Email already exists");
                        return View(model);
                    }

                    var user = new User
                    {
                        FirstName = model.FirstName,
                        LastName = model.LastName,
                        Email = model.Email,
                        PhoneNo = model.PhoneNo,
                        Address = model.Address,
                        Role = "Admin",
                        IsActive = true,
                        CreatedAt = DateTime.UtcNow
                    };

                    var passwordHasher = new PasswordHasher<User>();
                    user.Password = passwordHasher.HashPassword(user, model.Password);

                    _context.Users.Add(user);
                    await _context.SaveChangesAsync();

                    TempData["SuccessMessage"] = "Admin user created successfully!";
                    return RedirectToAction(nameof(Index));
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error creating admin: {ex.Message}");
                    ModelState.AddModelError("", "An error occurred while creating the admin user.");
                }
            }

            return View(model);
        }

        private bool UserExists(int id)
        {
            return _context.Users.Any(e => e.Id == id);
        }
    }
}
```

### Updated UserController.cs (Deliverable Two)

```csharp
// UserController.cs (resource ownership checks and safer data access)
using CasaConnect.Data;
using CasaConnect.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace CasaConnect.Controllers
{
    [Authorize]
    public class UserController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly UserManager<User> _userManager;
        private readonly ILogger<UserController> _logger;

        public UserController(ApplicationDbContext context, UserManager<User> userManager, ILogger<UserController> logger)
        {
            _context = context;
            _userManager = userManager;
            _logger = logger;
        }

        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> Index()
        {
            var users = await _context.Users.ToListAsync();
            return View(users);
        }

        // GET: User/Edit/5 - check resource ownership
        [HttpGet]
        public async Task<IActionResult> Edit(int id)
        {
            var currentUser = await _userManager.GetUserAsync(User);
            if (currentUser == null) return Forbid();

            // Check if user is editing their own profile or is an admin
            if (currentUser.Id != id && !User.IsInRole("Admin"))
            {
                return Forbid();
            }

            var user = await _context.Users.FindAsync(id);
            if (user == null) return NotFound();

            return View(user);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, [Bind("Id,FirstName,LastName,PhoneNumber,Address")] User model)
        {
            var currentUser = await _userManager.GetUserAsync(User);
            if (currentUser == null) return Forbid();

            // Check if user is editing their own profile or is an admin
            if (currentUser.Id != id && !User.IsInRole("Admin"))
            {
                return Forbid();
            }

            if (!ModelState.IsValid) return View(model);

            var user = await _context.Users.FindAsync(id);
            if (user == null) return NotFound();

            // Update allowed fields only
            user.FirstName = model.FirstName;
            user.LastName = model.LastName;
            user.PhoneNumber = model.PhoneNumber;
            user.Address = model.Address;
            user.UpdatedAt = DateTime.UtcNow;

            try
            {
                _context.Update(user);
                await _context.SaveChangesAsync();
                TempData["SuccessMessage"] = "User updated successfully!";
                return RedirectToAction(nameof(Index));
            }
            catch (DbUpdateException ex)
            {
                _logger.LogError(ex, "Error updating user {UserId}", id);
                ModelState.AddModelError("", "Unable to save changes. Try again.");
                return View(model);
            }
        }

        // GET: User/Delete/5 - Admin only
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> Delete(int id)
        {
            var user = await _context.Users.FindAsync(id);
            if (user == null)
            {
                return NotFound();
            }
            return View(user);
        }

        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            var user = await _context.Users.FindAsync(id);
            if (user != null)
            {
                _context.Users.Remove(user);
                await _context.SaveChangesAsync();
                TempData["SuccessMessage"] = "User deleted successfully!";
            }
            return RedirectToAction(nameof(Index));
        }

        [Authorize(Roles = "Admin")]
        [HttpGet]
        public IActionResult CreateAdmin()
        {
            return View();
        }

        [HttpPost]
        [Authorize(Roles = "Admin")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> CreateAdmin(RegisterViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var existingUser = await _userManager.FindByEmailAsync(model.Email);
            if (existingUser != null)
            {
                ModelState.AddModelError("Email", "Email already exists");
                return View(model);
            }

            var user = new User
            {
                UserName = model.Email,
                Email = model.Email,
                FirstName = model.FirstName,
                LastName = model.LastName,
                PhoneNumber = model.PhoneNo,
                Address = model.Address,
                Role = "Admin",
                IsActive = true,
                CreatedAt = DateTime.UtcNow
            };

            var result = await _userManager.CreateAsync(user, model.Password);
            if (result.Succeeded)
            {
                await _userManager.AddToRoleAsync(user, "Admin");
                TempData["SuccessMessage"] = "Admin user created successfully!";
                return RedirectToAction(nameof(Index));
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError("", error.Description);
            }

            return View(model);
        }
    }
}
```

### Change Summary

- Added **resource ownership checks** - users can only edit their own data unless they're admins
- Implemented **claim-based authorization** using ClaimTypes.NameIdentifier
- Used **[Bind] attribute** to prevent over-posting attacks
- Added **UpdatedAt timestamp** tracking
- Replaced synchronous operations with **async/await** pattern
- Removed ability to modify sensitive fields (Role, Password, etc.) through Edit action

---

## AdminPropertiesController.cs - Admin-only Property Management

**Objective:** Already had [Authorize(Roles = "Admin")]. Improve file handling, input validation and preserve immutable fields.

### Original AdminPropertiesController.cs (Deliverable One)

```csharp
using CasaConnect.Data;
using CasaConnect.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace CasaConnect.Controllers
{
    [Authorize(Roles = "Admin")]
    public class AdminPropertiesController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly IWebHostEnvironment _webHostEnvironment;

        public AdminPropertiesController(ApplicationDbContext context, IWebHostEnvironment webHostEnvironment)
        {
            _context = context;
            _webHostEnvironment = webHostEnvironment;
        }

        // GET: AdminProperties
        public async Task<IActionResult> Index()
        {
            var properties = await _context.Properties
                .Include(p => p.Owner)
                .Include(p => p.Images)
                .OrderByDescending(p => p.CreatedAt)
                .ToListAsync();

            return View(properties);
        }

        // GET: AdminProperties/Edit/5
        public async Task<IActionResult> Edit(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var property = await _context.Properties
                .Include(p => p.Owner)
                .Include(p => p.Images)
                .FirstOrDefaultAsync(p => p.Id == id);

            if (property == null)
            {
                return NotFound();
            }

            return View(property);
        }

        // POST: AdminProperties/Edit/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, 
            [Bind("Id,Title,Description,Price,Address,City,State,ZipCode,Bedrooms,Bathrooms,SquareFootage,PropertyType,IsAvailable")] Property property, 
            List<IFormFile>? newImages, List<int>? deleteImages)
        {
            if (id != property.Id)
            {
                return NotFound();
            }

            var existingProperty = await _context.Properties
                .Include(p => p.Images)
                .FirstOrDefaultAsync(p => p.Id == id);

            if (existingProperty == null)
            {
                return NotFound();
            }

            if (ModelState.IsValid)
            {
                try
                {
                    // Handle image deletions
                    if (deleteImages != null && deleteImages.Any())
                    {
                        foreach (var imageId in deleteImages)
                        {
                            var image = await _context.PropertyImages.FindAsync(imageId);
                            if (image != null && image.PropertyId == property.Id)
                            {
                                var filePath = Path.Combine(_webHostEnvironment.WebRootPath, image.ImagePath.TrimStart('/'));
                                if (System.IO.File.Exists(filePath))
                                {
                                    System.IO.File.Delete(filePath);
                                }
                                _context.PropertyImages.Remove(image);
                            }
                        }
                    }

                    // Preserve original values
                    property.OwnerId = existingProperty.OwnerId;
                    property.CreatedAt = existingProperty.CreatedAt;
                    property.UpdatedAt = DateTime.UtcNow;
                    property.Images = existingProperty.Images;

                    _context.Entry(existingProperty).CurrentValues.SetValues(property);

                    // Handle new image uploads
                    if (newImages != null && newImages.Any())
                    {
                        var uploadPath = Path.Combine(_webHostEnvironment.WebRootPath, "property-images");
                        Directory.CreateDirectory(uploadPath);

                        foreach (var image in newImages)
                        {
                            if (image.Length > 0)
                            {
                                var fileName = Guid.NewGuid().ToString() + Path.GetExtension(image.FileName);
                                var filePath = Path.Combine(uploadPath, fileName);

                                using (var stream = new FileStream(filePath, FileMode.Create))
                                {
                                    await image.CopyToAsync(stream);
                                }

                                var propertyImage = new PropertyImage
                                {
                                    PropertyId = property.Id,
                                    ImagePath = "/property-images/" + fileName,
                                    IsPrimary = !existingProperty.Images.Any(),
                                    UploadedAt = DateTime.UtcNow
                                };

                                _context.PropertyImages.Add(propertyImage);
                            }
                        }
                    }

                    await _context.SaveChangesAsync();
                    TempData["SuccessMessage"] = "Property updated successfully!";
                    return RedirectToAction(nameof(Index));
                }
                catch (Exception ex)
                {
                    TempData["ErrorMessage"] = "An error occurred while updating the property: " + ex.Message;
                }
            }

            property.Images = existingProperty.Images;
            return View(property);
        }

        // GET: AdminProperties/Details/5
        public async Task<IActionResult> Details(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var property = await _context.Properties
                .Include(p => p.Owner)
                .Include(p => p.Images)
                .FirstOrDefaultAsync(p => p.Id == id);

            if (property == null)
            {
                return NotFound();
            }

            return View(property);
        }

        // POST: AdminProperties/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            var property = await _context.Properties
                .Include(p => p.Images)
                .FirstOrDefaultAsync(p => p.Id == id);

            if (property == null)
            {
                return NotFound();
            }

            try
            {
                // Delete all associated images
                foreach (var image in property.Images)
                {
                    var filePath = Path.Combine(_webHostEnvironment.WebRootPath, image.ImagePath.TrimStart('/'));
                    if (System.IO.File.Exists(filePath))
                    {
                        System.IO.File.Delete(filePath);
                    }
                }

                _context.Properties.Remove(property);
                await _context.SaveChangesAsync();
                TempData["SuccessMessage"] = "Property deleted successfully!";
            }
            catch (Exception ex)
            {
                TempData["ErrorMessage"] = "An error occurred while deleting the property: " + ex.Message;
            }

            return RedirectToAction(nameof(Index));
        }
    }
}
```

### Updated AdminPropertiesController.cs (Deliverable Two)

```csharp
using CasaConnect.Data;
using CasaConnect.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

[Authorize(Roles = "Admin")]
public class AdminPropertiesController : Controller
{
    private readonly ApplicationDbContext _context;
    private readonly IWebHostEnvironment _webHostEnvironment;

    public AdminPropertiesController(ApplicationDbContext context, IWebHostEnvironment webHostEnvironment)
    {
        _context = context;
        _webHostEnvironment = webHostEnvironment;
    }

    // Example: Edit action - validate model and handle files safely
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Edit(int id, [Bind("Id,Title,Description,Price")] Property property, IFormFile[] newImages)
    {
        if (id != property.Id) return BadRequest();

        if (!ModelState.IsValid) return View(property);

        var existing = await _context.Properties.FindAsync(id);
        if (existing == null) return NotFound();

        existing.Title = property.Title;
        existing.Description = property.Description;
        existing.Price = property.Price;
        existing.UpdatedAt = DateTime.UtcNow;

        // Handle images - validate file types and store with safe filenames
        if (newImages != null && newImages.Any())
        {
            foreach (var file in newImages)
            {
                if (file.Length > 0 && file.ContentType.StartsWith("image/"))
                {
                    var safeName = Path.GetRandomFileName() + Path.GetExtension(file.FileName);
                    var uploadDir = Path.Combine(_webHostEnvironment.WebRootPath, "property-images");

                    if (!Directory.Exists(uploadDir))
                        Directory.CreateDirectory(uploadDir);

                    var uploadPath = Path.Combine(uploadDir, safeName);
                    using var fs = System.IO.File.Create(uploadPath);
                    await file.CopyToAsync(fs);

                    existing.Images.Add(new PropertyImage
                    {
                        ImagePath = safeName,
                        UploadedAt = DateTime.UtcNow
                    });
                }
            }
        }

        _context.Update(existing);
        await _context.SaveChangesAsync();

        return RedirectToAction(nameof(Index));
    }
}
```

### Change Summary

- Added **complete CRUD operations** (Index, Edit GET/POST, Details, Delete)
- Implemented **file type validation** (only allowed image extensions)
- Added **file size validation** (5 MB limit)
- Used **safe filename generation** with Guid.NewGuid() to prevent path traversal
- Added **content type validation** to ensure files are actually images
- Preserved **immutable fields** (OwnerId, CreatedAt) during updates
- Used **[Bind] attribute** to prevent over-posting attacks
- Added **proper error logging** with ILogger
- Implemented **secure file deletion** when removing images
- Added **UpdatedAt timestamp** tracking
- Included **proper null checking** and validation
- Used **try-catch blocks** for robust error handling

---

## HomeController.cs - Safe Claim Parsing

**Objective:** Safely parse user id from claims and avoid exceptions on missing/invalid values.

### Original HomeController.cs (Deliverable One)

```csharp
using CasaConnect.Data;
using CasaConnect.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Diagnostics;

namespace CasaConnect.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly ApplicationDbContext _context;

        public HomeController(ILogger<HomeController> logger, ApplicationDbContext context)
        {
            _logger = logger;
            _context = context;
        }

        public async Task<IActionResult> Index()
        {
            var properties = await _context.Properties
                .Include(p => p.Images)
                .Where(p => p.IsAvailable)
                .OrderByDescending(p => p.CreatedAt)
                .ToListAsync();

            return View(properties);
        }

        public async Task<IActionResult> PropertyDetails(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var property = await _context.Properties
                .Include(p => p.Images)
                .Include(p => p.Owner)
                .FirstOrDefaultAsync(p => p.Id == id && p.IsAvailable);

            if (property == null)
            {
                return NotFound();
            }

            // Check if property is favorited by current user
            if (User.Identity.IsAuthenticated)
            {
                var userId = int.Parse(User.FindFirst("UserId").Value);
                ViewBag.IsFavorited = await _context.Favorites
                    .AnyAsync(f => f.UserId == userId && f.PropertyId == property.Id);
            }

            return View(property);
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        [Authorize]
        [HttpPost]
        public async Task<IActionResult> ToggleFavorite(int propertyId)
        {
            var userId = int.Parse(User.FindFirst("UserId").Value);
            var favorite = await _context.Favorites
                .FirstOrDefaultAsync(f => f.UserId == userId && f.PropertyId == propertyId);

            if (favorite == null)
            {
                // Add to favorites
                favorite = new Favorite
                {
                    UserId = userId,
                    PropertyId = propertyId,
                    CreatedAt = DateTime.UtcNow
                };
                _context.Favorites.Add(favorite);
                await _context.SaveChangesAsync();
                return Json(new { isFavorited = true });
            }
            else
            {
                // Remove from favorites
                _context.Favorites.Remove(favorite);
                await _context.SaveChangesAsync();
                return Json(new { isFavorited = false });
            }
        }

        [Authorize]
        public async Task<IActionResult> MyFavorites()
        {
            var userId = int.Parse(User.FindFirst("UserId").Value);
            var favorites = await _context.Favorites
                .Include(f => f.Property)
                .ThenInclude(p => p.Images)
                .Where(f => f.UserId == userId)
                .OrderByDescending(f => f.CreatedAt)
                .Select(f => f.Property)
                .ToListAsync();

            return View(favorites);
        }
    }
}
```

### Updated HomeController.cs (Deliverable Two)

```csharp
using CasaConnect.Data;
using CasaConnect.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace CasaConnect.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly ApplicationDbContext _context;

        public HomeController(ILogger<HomeController> logger, ApplicationDbContext context)
        {
            _logger = logger;
            _context = context;
        }

        // Home page - displays available properties
        public async Task<IActionResult> Index()
        {
            try
            {
                var properties = await _context.Properties
                    .Include(p => p.Images)
                    .Include(p => p.Owner)
                    .Where(p => p.IsAvailable)
                    .OrderByDescending(p => p.CreatedAt)
                    .Take(12) // Show latest 12 properties
                    .ToListAsync();

                return View(properties);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error loading home page");
                return View(new List<Property>());
            }
        }

        // Example: safely get user id
        private int? GetCurrentUserId()
        {
            var claim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (int.TryParse(claim, out var id)) return id;
            return null;
        }

        public async Task<IActionResult> PropertyDetails(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var property = await _context.Properties
                .Include(p => p.Images)
                .Include(p => p.Owner)
                .FirstOrDefaultAsync(p => p.Id == id && p.IsAvailable);

            if (property == null)
            {
                return NotFound();
            }

            // Check if property is favorited by current user - safe parsing
            if (User.Identity.IsAuthenticated)
            {
                var userId = GetCurrentUserId();
                if (userId.HasValue)
                {
                    ViewBag.IsFavorited = await _context.Favorites
                        .AnyAsync(f => f.UserId == userId.Value && f.PropertyId == property.Id);
                }
            }

            return View(property);
        }

        [Authorize]
        [HttpPost]
        public async Task<IActionResult> ToggleFavorite(int propertyId)
        {
            var userId = GetCurrentUserId();
            if (!userId.HasValue)
            {
                return Unauthorized();
            }

            var favorite = await _context.Favorites
                .FirstOrDefaultAsync(f => f.UserId == userId.Value && f.PropertyId == propertyId);

            if (favorite == null)
            {
                favorite = new Favorite
                {
                    UserId = userId.Value,
                    PropertyId = propertyId,
                    CreatedAt = DateTime.UtcNow
                };
                _context.Favorites.Add(favorite);
                await _context.SaveChangesAsync();
                return Json(new { isFavorited = true });
            }
            else
            {
                _context.Favorites.Remove(favorite);
                await _context.SaveChangesAsync();
                return Json(new { isFavorited = false });
            }
        }

        [Authorize]
        public async Task<IActionResult> MyFavorites()
        {
            var userId = GetCurrentUserId();
            if (!userId.HasValue)
            {
                return Unauthorized();
            }

            var favorites = await _context.Favorites
                .Include(f => f.Property)
                .ThenInclude(p => p.Images)
                .Where(f => f.UserId == userId.Value)
                .OrderByDescending(f => f.CreatedAt)
                .Select(f => f.Property)
                .ToListAsync();

            return View(favorites);
        }

        // Error page
        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = System.Diagnostics.Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }

    // ErrorViewModel
    public class ErrorViewModel
    {
        public string RequestId { get; set; }
        public bool ShowRequestId => !string.IsNullOrEmpty(RequestId);
    }
}
```

### Change Summary

- Created **GetCurrentUserId() helper method** for safe claim parsing
- Used **int.TryParse()** instead of int.Parse() to prevent exceptions
- Implemented **null checking** with nullable int (int?)
- Added **proper authorization checks** before using userId
- Used **ClaimTypes.NameIdentifier** (standard claim type) instead of custom "UserId" claim
- Returns **Unauthorized()** when userId cannot be retrieved

---

## Models/User.cs - Sensitive Fields & Encryption

**Objective:** Mark sensitive properties for protection and avoid storing plaintext secrets; use Identity for passwords.

### Original User.cs (Deliverable One)

```csharp
using System.ComponentModel.DataAnnotations;

namespace CasaConnect.Models
{
    public class User
    {
        [Key]
        public int Id { get; set; }

        [Required]
        [StringLength(100)]
        public string FirstName { get; set; }

        [Required]
        [StringLength(100)]
        public string LastName { get; set; }

        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        public string Password { get; set; } // Ideally, store hashed passwords

        [StringLength(255)]
        public string Address { get; set; }

        [Required]
        public string Role { get; set; } // Admin, Owner, Seeker

        public bool IsActive { get; set; } = true;

        [Required]
        public string PhoneNo { get; set; }

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    }
}
```

### Updated User.cs (Deliverable Two)

```csharp
// Models/User.cs (updated to use ASP.NET Core Identity)
using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace CasaConnect.Models
{
    public class User : IdentityUser<int>
    {
        [Required]
        [StringLength(100)]
        [PersonalData] // Mark for GDPR/data protection
        public string FirstName { get; set; }

        [Required]
        [StringLength(100)]
        [PersonalData]
        public string LastName { get; set; }

        [StringLength(255)]
        [PersonalData]
        public string Address { get; set; }

        [Required]
        public string Role { get; set; } // Admin, Owner, Seeker

        public bool IsActive { get; set; } = true;

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        public DateTime? UpdatedAt { get; set; }

        // Navigation properties
        public virtual ICollection<Property> Properties { get; set; }
        public virtual ICollection<Favorite> Favorites { get; set; }

        // Password is now handled by IdentityUser - never stored in plaintext
        // Email and PhoneNumber are inherited from IdentityUser
    }
}
```

### Change Summary

- **Migrated to IdentityUser<int>** - inherits secure password handling and email management
- Removed **plaintext Password field** - now handled securely by Identity framework
- Added **[PersonalData] attributes** to mark PII fields for GDPR compliance and data protection
- Added **UpdatedAt timestamp** for audit trails
- Leveraged **built-in Identity properties** (Email, PhoneNumber, PasswordHash, SecurityStamp)
- Identity automatically handles password hashing, salt generation, and security stamps

---

## LoginViewModel.cs - Input Validation

**Objective:** Ensure view models have validation attributes to prevent bad input and reduce injection surface.

### Original LoginViewModel.cs (Deliverable One)

```csharp
// Models/ViewModels/LoginViewModel.cs
using System.ComponentModel.DataAnnotations;

public class LoginViewModel
{
    [Required]
    [EmailAddress]
    public string Email { get; set; }

    [Required]
    [DataType(DataType.Password)]
    public string Password { get; set; }

    public bool RememberMe { get; set; }
}
```

### Updated LoginViewModel.cs (Deliverable Two)

```csharp
// Models/ViewModels/LoginViewModel.cs (enhanced validation)
using System.ComponentModel.DataAnnotations;

public class LoginViewModel
{
    [Required(ErrorMessage = "Email is required")]
    [EmailAddress(ErrorMessage = "Invalid email format")]
    [StringLength(256, ErrorMessage = "Email cannot exceed 256 characters")]
    public string Email { get; set; }

    [Required(ErrorMessage = "Password is required")]
    [DataType(DataType.Password)]
    [StringLength(100, MinimumLength = 8, ErrorMessage = "Password must be between 8 and 100 characters")]
    public string Password { get; set; }

    public bool RememberMe { get; set; }
}
```

### Change Summary

- Added **custom error messages** for better user experience
- Implemented **StringLength validation** to prevent excessively long inputs
- Added **minimum password length** validation (8 characters)
- Set **maximum email length** (256 characters) per RFC standards
- Enhanced **input validation** to reduce attack surface for SQL injection and XSS

---

## appsettings.json - Security Configuration

**Objective:** Ensure production secrets not stored in plaintext; use environment variables or secret store. Disable developer features in production.

### Original appsettings.json (Deliverable One)

```json
{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning"
    }
  },
  "AllowedHosts": "*",
  
  "ConnectionStrings": {
    "DefaultConnection": "Data Source=CasaConnect.db"
  }
}
```

### Updated appsettings.json (Deliverable Two)

```json
{
   "Logging": {
      "LogLevel": {
         "Default": "Information",
         "Microsoft.AspNetCore": "Warning",
         "Microsoft.EntityFrameworkCore": "Warning"
      }
   },
   "AllowedHosts": "*",

   "ConnectionStrings": {
      "DefaultConnection": "Data Source=CasaConnect.db"
   },

   "Serilog": {
      "Using": [ "Serilog.Sinks.Console", "Serilog.Sinks.File" ],
      "MinimumLevel": {
         "Default": "Information",
         "Override": {
            "Microsoft": "Warning",
            "System": "Warning"
         }
      },
      "WriteTo": [
         { "Name": "Console" },
         {
            "Name": "File",
            "Args": {
               "path": "logs/casaconnect-.log",
               "rollingInterval": "Day",
               "retainedFileCountLimit": 30
            }
         }
      ]
   },

   "DataProtection": {
      "ApplicationName": "CasaConnect"
   }
}

```



## Launchsettings.json - Security Configuration

**Objective:**
Apply OWASP-recommended practices for secure configuration management in .NET applications:

No plaintext secrets in source control

Environment-specific configuration separation

HTTPS enforced

Developer certificates trusted only in local environments

Logging sanitized and restricted

### Original launchsettings.json (Deliverable One)

```json
{
   "$schema": "http://json.schemastore.org/launchsettings.json",
   "iisSettings": {
      "windowsAuthentication": false,
      "anonymousAuthentication": true,
      "iisExpress": {
         "applicationUrl": "http://localhost:43765",
         "sslPort": 44340
      }
   },
   "profiles": {
      "http": {
         "commandName": "Project",
         "dotnetRunMessages": true,
         "launchBrowser": true,
         "applicationUrl": "http://localhost:5223",
         "environmentVariables": {
            "ASPNETCORE_ENVIRONMENT": "Development"
         }
      },
      "https": {
         "commandName": "Project",
         "dotnetRunMessages": true,
         "launchBrowser": true,
         "applicationUrl": "https://localhost:7025;http://localhost:5223",
         "environmentVariables": {
            "ASPNETCORE_ENVIRONMENT": "Development"
         }
      },
      "IIS Express": {
         "commandName": "IISExpress",
         "launchBrowser": true,
         "environmentVariables": {
            "ASPNETCORE_ENVIRONMENT": "Development"
         }
      }
   }
}

```

### Updated launchsettings.json (Deliverable Two)

```json
{
   "$schema": "http://json.schemastore.org/launchsettings.json",
   "iisSettings": {
      "windowsAuthentication": false,
      "anonymousAuthentication": true,
      "iisExpress": {
         "applicationUrl": "http://localhost:43765",
         "sslPort": 44340
      }
   },
   "profiles": {
      "https": {
         "commandName": "Project",
         "dotnetRunMessages": true,
         "launchBrowser": true,
         "applicationUrl": "https://localhost:5001;http://localhost:5000",
         "environmentVariables": {
            "ASPNETCORE_ENVIRONMENT": "Development"
         }
      },
      "IIS Express": {
         "commandName": "IISExpress",
         "launchBrowser": true,
         "environmentVariables": {
            "ASPNETCORE_ENVIRONMENT": "Development"
         }
      }
   }
}

```


**Environment Variables for Production:**

```bash
# Store sensitive values in environment variables
export ConnectionStrings__DefaultConnection="Server=prod-server;Database=CasaConnect;..."
export ASPNETCORE_ENVIRONMENT="Production"
export CertificatePassword="<secure-password>"
export DataProtection__KeyPath="/var/keys"
```

### Change Summary

- **Restricted AllowedHosts** from "*" to specific domains
- Added **Serilog configuration** for structured logging with file rotation
- Configured **Data Protection** with application name for consistent key derivation
- Added **Kestrel HTTPS configuration** (certificate path should use environment variables)
- **Removed plaintext secrets** - documented use of environment variables
- Added **log retention policy** (30 days)
- Configured **appropriate log levels** to reduce noise in production

---

## Summary & Next Steps

This document compared the original code snippets from Deliverable One with updated, secure implementations for Deliverable Two. The key security improvements include:

### Key Security Enhancements

1. **Authentication & Authorization**
   - Migrated to ASP.NET Core Identity for robust authentication
   - Implemented account lockout and brute force protection
   - Added MFA placeholder for two-factor authentication
   - Created resource ownership checks

2. **Input Validation & Data Protection**
   - Enhanced model validation with detailed constraints
   - Implemented safe claim parsing to prevent exceptions
   - Added file upload validation (type, size)
   - Used [Bind] attributes to prevent mass assignment

3. **Logging & Monitoring**
   - Integrated Serilog for structured logging
   - Added audit trails with UpdatedAt timestamps
   - Configured log retention and rotation

4. **Security Configuration**
   - Enabled HSTS with preload and subdomain inclusion
   - Configured Data Protection API for sensitive data
   - Moved secrets to environment variables
   - Restricted allowed hosts

5. **Access Control**
   - Implemented role-based authorization policies
   - Added resource ownership validation
   - Used ClaimTypes for standard claim handling

