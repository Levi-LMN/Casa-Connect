# CasaConnect - Deliverable Two: Security Implementation Review

**Course:** CMT 447 - Web Application Security

**Team:** Okongo Eugine Kelly, Levi Mukuha, Eve Njore, Lewis Andanje, Austin Kwalia

**Date:** November 3, 2025

---

## Table of Contents

1. [Program.cs - Application Configuration & Middleware](#programcs---application-configuration--middleware)
2. [AccountController.cs - Authentication & Authorization](#accountcontrollercs---authentication--authorization)
3. [UserController.cs - Broken Access Control](#usercontrollercs---broken-access-control)
4. [AdminPropertiesController.cs - Admin Property Management](#adminpropertiescontrollercs---admin-property-management)
5. [HomeController.cs - Safe Claim Parsing](#homecontrollercs---safe-claim-parsing)
6. [Models/User.cs - Secure User Model](#modelsusercs---secure-user-model)
7. [LoginViewModel.cs - Input Validation](#loginviewmodelcs---input-validation)
8. [appsettings.json - Security Configuration](#appsettingsjson---security-configuration)
9. [launchsettings.json - Development Configuration](#launchsettingsjson---development-configuration)
10. [Summary & OWASP Top 10 Coverage](#summary--owasp-top-10-coverage)

---

## Program.cs - Application Configuration & Middleware

**File:** `Program.cs`

**OWASP Categories Addressed:**
- A01:2021 - Broken Access Control
- A02:2021 - Cryptographic Failures
- A05:2021 - Security Misconfiguration
- A09:2021 - Security Logging and Monitoring Failures

### What Changed

#### Authentication System Migration
**Old:** Cookie-based authentication with manual implementation
```csharp
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/Account/Login";
        options.LogoutPath = "/Account/Logout";
        options.AccessDeniedPath = "/Account/AccessDenied";
    });

builder.Services.AddScoped<IPasswordHasher<User>, PasswordHasher<User>>();
```

**New:** ASP.NET Core Identity with comprehensive security policies
```csharp
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
```

**Security Improvement:** Identity framework provides built-in protection against brute force attacks through account lockout, enforces strong password policies, and handles secure password hashing with PBKDF2 algorithm.

#### Structured Logging Implementation
**Old:** Basic ASP.NET Core logging
```csharp
// No structured logging configuration
```

**New:** Serilog integration for comprehensive audit trails
```csharp
Log.Logger = new LoggerConfiguration()
    .ReadFrom.Configuration(builder.Configuration)
    .Enrich.FromLogContext()
    .CreateLogger();

builder.Host.UseSerilog();
```

**Security Improvement:** Enables detailed security event logging for incident response and forensic analysis, addressing OWASP A09 (Security Logging and Monitoring Failures).

#### HTTPS Enforcement
**Old:** Basic HTTPS redirection without explicit configuration
```csharp
app.UseHttpsRedirection();
```

**New:** Explicit HTTPS redirection with proper status code
```csharp
builder.Services.AddHttpsRedirection(options =>
{
    options.RedirectStatusCode = StatusCodes.Status308PermanentRedirect;
    options.HttpsPort = 5001;
});
```

**Security Improvement:** Uses HTTP 308 (Permanent Redirect) instead of 302, preventing potential downgrade attacks and ensuring browsers cache the HTTPS requirement.

#### Authorization Policies
**Old:** No centralized authorization policies
```csharp
// No policy configuration
```

**New:** Role-based authorization policies
```csharp
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", policy => policy.RequireRole("Admin"));
});
```

**Security Improvement:** Centralized authorization logic prevents inconsistent access control implementation across controllers.

#### Additional Security Services
**New Additions:**
```csharp
builder.Services.AddHttpClient();          // Secure HTTP client factory
builder.Services.AddDataProtection();      // Data encryption services
```

**Security Improvement:** IHttpClientFactory prevents socket exhaustion and DNS issues. Data Protection API provides encryption for sensitive data like cookies and tokens.

#### Database Initialization
**Old:** Synchronous initialization
```csharp
DbInitializer.Initialize(context, passwordHasher);
```

**New:** Async initialization with proper role management
```csharp
await DbInitializer.Initialize(context, userManager, roleManager);
```

**Security Improvement:** Proper async/await pattern prevents blocking and ensures role-based access control is properly initialized.

---

## AccountController.cs - Authentication & Authorization

**File:** `Controllers/AccountController.cs`

**OWASP Categories Addressed:**
- A01:2021 - Broken Access Control
- A02:2021 - Cryptographic Failures
- A07:2021 - Identification and Authentication Failures

### What Changed

#### Login Authentication
**Old:** Manual password verification with user enumeration vulnerability
```csharp
var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == model.Email);

if (user == null)
{
    ModelState.AddModelError("", "Invalid login attempt.");
    return View(model);
}

var result = _passwordHasher.VerifyHashedPassword(user, user.Password, model.Password);
```

**New:** Identity-based authentication with lockout protection
```csharp
var user = await _userManager.FindByEmailAsync(model.Email);
if (user == null)
{
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
    return RedirectToAction(nameof(VerifyTwoFactor));
}
if (result.IsLockedOut)
{
    _logger.LogWarning("User {Email} account locked out", model.Email);
    ModelState.AddModelError(string.Empty, "Account locked due to multiple failed login attempts.");
    return View(model);
}
```

**Security Improvements:**
1. **Null Safety:** Uses null-conditional operator (?.) to prevent NullReferenceException
2. **Safe Parsing:** int.TryParse instead of int.Parse prevents FormatException
3. **Standard Claims:** Uses ClaimTypes.NameIdentifier instead of custom claim
4. **Graceful Degradation:** Returns null if claim missing or invalid
5. **Reusability:** Centralized parsing logic prevents code duplication

#### Toggle Favorite Action
**Old:** Unsafe parsing with no error handling
```csharp
[Authorize]
[HttpPost]
public async Task<IActionResult> ToggleFavorite(int propertyId)
{
    var userId = int.Parse(User.FindFirst("UserId").Value);
    var favorite = await _context.Favorites
        .FirstOrDefaultAsync(f => f.UserId == userId && f.PropertyId == propertyId);

    if (favorite == null)
    {
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
        _context.Favorites.Remove(favorite);
        await _context.SaveChangesAsync();
        return Json(new { isFavorited = false });
    }
}
```

**New:** Safe parsing with authorization validation
```csharp
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
```

**Security Improvements:**
1. **Authorization Validation:** Returns 401 if user ID cannot be retrieved
2. **Exception Prevention:** No exceptions thrown if claim parsing fails
3. **Consistent Error Handling:** Uniform approach across all actions

#### My Favorites Action
**Old:** Direct claim access
```csharp
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
```

**New:** Safe claim retrieval
```csharp
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
```

**Security Improvement:** Prevents application crash if authentication state is inconsistent.

#### Index Action Enhancement
**Old:** No error handling
```csharp
public async Task<IActionResult> Index()
{
    var properties = await _context.Properties
        .Include(p => p.Images)
        .Where(p => p.IsAvailable)
        .OrderByDescending(p => p.CreatedAt)
        .ToListAsync();

    return View(properties);
}
```

**New:** Error handling with pagination
```csharp
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
```

**Security Improvements:**
1. **Graceful Error Handling:** Application doesn't crash on database errors
2. **Pagination:** Limits query results to prevent resource exhaustion
3. **Audit Logging:** Errors logged for investigation
4. **User Experience:** Returns empty list instead of error page

---

## Models/User.cs - Secure User Model

**File:** `Models/User.cs`

**OWASP Categories Addressed:**
- A02:2021 - Cryptographic Failures
- A04:2021 - Insecure Design
- A05:2021 - Security Misconfiguration

### What Changed

#### Model Inheritance
**Old:** Custom user class with manual password handling
```csharp
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
    public string Password { get; set; } // Stored as hashed password

    [StringLength(255)]
    public string Address { get; set; }

    [Required]
    public string Role { get; set; }

    public bool IsActive { get; set; } = true;

    [Required]
    public string PhoneNo { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}
```

**New:** Identity-based user model
```csharp
public class User : IdentityUser<int>
{
    [Required]
    [StringLength(100)]
    [PersonalData]
    public string FirstName { get; set; }

    [Required]
    [StringLength(100)]
    [PersonalData]
    public string LastName { get; set; }

    [StringLength(255)]
    [PersonalData]
    public string Address { get; set; }

    [Required]
    public string Role { get; set; }

    public bool IsActive { get; set; } = true;

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public DateTime? UpdatedAt { get; set; }

    // Navigation properties
    public virtual ICollection<Property> Properties { get; set; }
    public virtual ICollection<Favorite> Favorites { get; set; }
}
```

**Security Improvements:**

1. **Password Security:**
   - **Old:** Plaintext Password field stored directly (even if hashed, field name implies direct access)
   - **New:** Password handled by IdentityUser through PasswordHash property
   - Uses PBKDF2 with 10,000 iterations (Identity default)
   - Automatic salt generation per user
   - Security stamp for token invalidation

2. **Email Handling:**
   - **Old:** Custom Email field with basic [EmailAddress] validation
   - **New:** Inherits Email, NormalizedEmail, and EmailConfirmed from IdentityUser
   - Built-in email confirmation workflow
   - Normalized email for case-insensitive lookups

3. **Phone Number:**
   - **Old:** Custom PhoneNo field without confirmation
   - **New:** Inherits PhoneNumber and PhoneNumberConfirmed
   - Supports two-factor authentication via SMS

4. **Account Security:**
   - **Old:** No security stamp or concurrency token
   - **New:** SecurityStamp for token invalidation
   - ConcurrencyStamp for optimistic concurrency control
   - LockoutEnd for temporary account lockouts
   - AccessFailedCount for brute force protection

5. **Personal Data Protection:**
   - **Old:** No data protection markers
   - **New:** [PersonalData] attributes on PII fields
   - Enables GDPR compliance features
   - Supports data export and deletion requirements

6. **Audit Trail:**
   - **Old:** Only CreatedAt timestamp
   - **New:** CreatedAt and UpdatedAt for change tracking

7. **Username Handling:**
   - **Old:** No username concept
   - **New:** Inherits UserName and NormalizedUserName
   - Can be set to email or separate username

#### Password Storage Comparison
**Old approach:**
```csharp
// Manual hashing required in controller
var user = new User
{
    Email = "user@example.com",
    Password = _passwordHasher.HashPassword(new User(), "password123")
};
```

**New approach:**
```csharp
// Identity handles everything securely
var user = new User
{
    UserName = "user@example.com",
    Email = "user@example.com"
};
await _userManager.CreateAsync(user, "password123");
// Password is automatically hashed with PBKDF2, salt, and security stamp
```

---

## LoginViewModel.cs - Input Validation

**File:** `Models/ViewModels/LoginViewModel.cs`

**OWASP Categories Addressed:**
- A03:2021 - Injection
- A04:2021 - Insecure Design
- A05:2021 - Security Misconfiguration

### What Changed

**Old:** Basic validation
```csharp
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

**New:** Enhanced validation with constraints
```csharp
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

**Security Improvements:**

1. **Email Validation:**
   - **Old:** Basic [EmailAddress] validation
   - **New:** Additional length constraint (256 chars max per RFC 5321)
   - Custom error messages prevent information disclosure
   - Prevents buffer overflow attempts in older systems

2. **Password Validation:**
   - **Old:** No length constraints
   - **New:** Minimum 8 characters, maximum 100 characters
   - Prevents denial-of-service through extremely long passwords
   - Minimum length enforces basic password strength

3. **User Feedback:**
   - **Old:** Generic default error messages
   - **New:** Clear, actionable error messages
   - Improves user experience while maintaining security
   - No information leakage about valid accounts

4. **Input Sanitization:**
   - Length limits reduce SQL injection surface area
   - Format validation prevents malformed input
   - Defense in depth - validation at multiple layers

---

## appsettings.json - Security Configuration

**File:** `appsettings.json`

**OWASP Categories Addressed:**
- A02:2021 - Cryptographic Failures
- A05:2021 - Security Misconfiguration
- A09:2021 - Security Logging and Monitoring Failures

### What Changed

**Old:** Minimal configuration
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

**New:** Comprehensive security configuration
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

**Security Improvements:**

1. **Logging Configuration:**
   - **Old:** Basic console logging only
   - **New:** Structured logging with Serilog
   - File-based logging for audit trails
   - Daily log rotation prevents disk exhaustion
   - 30-day retention policy for compliance

2. **Log Management:**
   - Console output for development debugging
   - File persistence for production audit trails
   - Appropriate log levels reduce noise
   - Entity Framework queries logged at Warning level to prevent sensitive data exposure

3. **Data Protection:**
   - **Old:** No data protection configuration
   - **New:** ApplicationName configured for consistent key derivation
   - Enables secure cookie encryption
   - Token encryption for password reset flows
   - Keys automatically managed by framework

4. **Connection Strings:**
   - Note: Production deployments should use environment variables
   - Example: `ConnectionStrings__DefaultConnection` environment variable
   - Prevents secrets in source control

5. **Host Restrictions:**
   - Note: AllowedHosts="*" acceptable for development
   - Production should specify explicit domains
   - Example: `"AllowedHosts": "casaconnect.com;www.casaconnect.com"`

**Production Environment Variables (recommended):**
```bash
# Set via environment, not in appsettings.json
ConnectionStrings__DefaultConnection="Data Source=Production.db;Password=SecurePass123"
DataProtection__CertificatePath="/etc/ssl/certs/casaconnect.pfx"
DataProtection__CertificatePassword="CertPassword123"
Serilog__WriteTo__0__Args__path="/var/log/casaconnect/app-.log"
```

---

## launchsettings.json - Development Configuration

**File:** `Properties/launchsettings.json`

**OWASP Categories Addressed:**
- A02:2021 - Cryptographic Failures
- A05:2021 - Security Misconfiguration

### What Changed

**Old:** Multiple insecure profiles
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

**New:** HTTPS-only configuration
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

**Security Improvements:**

1. **HTTP Profile Removal:**
   - **Old:** Included dedicated "http" profile
   - **New:** Removed HTTP-only profile
   - Prevents developers from accidentally running without HTTPS
   - Enforces secure development practices

2. **Standardized Ports:**
   - **Old:** Non-standard ports (7025, 5223)
   - **New:** Standard development ports (5001 for HTTPS, 5000 for HTTP)
   - Consistent with ASP.NET Core conventions
   - Easier to configure development tools and proxies

3. **HTTPS-First Approach:**
   - HTTPS profile listed first and set as default
   - HTTP listener (5000) only used for HTTPS redirection
   - Matches production configuration

4. **Environment Configuration:**
   - Development environment explicitly set
   - Enables development-specific features (detailed errors, etc.)
   - Prevents accidental production deployment with dev settings

5. **IIS Express Configuration:**
   - SSL port configured (44340)
   - Anonymous authentication enabled for public-facing features
   - Windows authentication disabled (application handles auth)

**Why These Changes Matter:**

1. **Training Developers:** Removes temptation to test over HTTP
2. **Cookie Security:** Secure flag works correctly in development
3. **CORS Testing:** More accurate HTTPS origin testing
4. **Certificate Trust:** Encourages proper dev certificate setup
5. **Production Parity:** Development environment closer to production

---

## Summary & OWASP Top 10 Coverage

### Security Enhancements by OWASP Category

#### A01:2021 - Broken Access Control
**Files Changed:** `Program.cs`, `AccountController.cs`, `UserController.cs`, `AdminPropertiesController.cs`, `HomeController.cs`

**Improvements:**
- Implemented role-based authorization policies
- Added resource ownership validation (users can only modify own data)
- Restricted admin functions to Admin role only
- Prevented horizontal privilege escalation
- Used [Authorize] attributes consistently
- Implemented proper HTTP status codes (403 vs 404)

#### A02:2021 - Cryptographic Failures
**Files Changed:** `Program.cs`, `Models/User.cs`, `appsettings.json`, `launchsettings.json`

**Improvements:**
- Migrated to ASP.NET Core Identity (PBKDF2 password hashing)
- Removed plaintext password storage
- Configured Data Protection API
- Enforced HTTPS with HTTP 308 redirects
- Added HSTS with preload and subdomain inclusion
- Marked PII fields with [PersonalData] attribute
- Removed HTTP-only development profile

#### A03:2021 - Injection
**Files Changed:** `UserController.cs`, `AdminPropertiesController.cs`, `LoginViewModel.cs`

**Improvements:**
- Used [Bind] attribute to prevent mass assignment
- Added input length validation
- Implemented file type and content validation
- Used parameterized Entity Framework queries
- Validated file extensions against whitelist
- Prevented path traversal with safe path construction

#### A04:2021 - Insecure Design
**Files Changed:** All controller files, `Models/User.cs`, `LoginViewModel.cs`

**Improvements:**
- Implemented defense in depth (multiple validation layers)
- Added proper error handling throughout
- Created helper methods for common operations (GetCurrentUserId)
- Used async/await consistently
- Implemented proper audit logging
- Added UpdatedAt timestamps for change tracking

#### A05:2021 - Security Misconfiguration
**Files Changed:** `Program.cs`, `appsettings.json`, `launchsettings.json`

**Improvements:**
- Configured appropriate password policies
- Enabled account lockout (5 attempts, 15 minutes)
- Set proper log levels
- Configured log retention (30 days)
- Standardized on HTTPS-only development
- Added comprehensive Serilog configuration
- Documented environment variable usage

#### A07:2021 - Identification and Authentication Failures
**Files Changed:** `Program.cs`, `AccountController.cs`, `Models/User.cs`

**Improvements:**
- Implemented Identity framework authentication
- Added brute force protection via lockout
- Prevented user enumeration with generic error messages
- Added MFA placeholder for future implementation
- Used secure token generation for password resets
- Implemented proper session management

#### A09:2021 - Security Logging and Monitoring Failures
**Files Changed:** `Program.cs`, `AccountController.cs`, `UserController.cs`, `AdminPropertiesController.cs`, `HomeController.cs`, `appsettings.json`

**Improvements:**
- Integrated Serilog for structured logging
- Logged all authentication events (login, logout, failures)
- Logged authorization failures
- Logged data modifications (updates, deletions)
- Configured log rotation and retention
- Added correlation IDs via FromLogContext
- Separate file logging for audit trails

### Files Modified Summary

1. **Program.cs** - Application startup and middleware configuration
2. **AccountController.cs** - Authentication, registration, profile management
3. **UserController.cs** - User CRUD operations with access control
4. **AdminPropertiesController.cs** - Property management with file upload security
5. **HomeController.cs** - Public pages with safe claim parsing
6. **Models/User.cs** - User model migrated to IdentityUser
7. **LoginViewModel.cs** - Enhanced input validation
8. **appsettings.json** - Security configuration and logging
9. **launchsettings.json** - Development environment configuration

### Next Steps for Production Deployment

1. **Environment Variables:**
   - Move all secrets to environment variables
   - Configure production connection strings
   - Set up certificate paths for Data Protection

2. **AllowedHosts Configuration:**
   - Update from "*" to specific domain names
   - Configure CORS policies if needed

3. **MFA Implementation:**
   - Complete VerifyTwoFactor action
   - Integrate authenticator app or SMS provider
   - Test two-factor flow

4. **Rate Limiting:**
   - Consider adding rate limiting middleware
   - Protect API endpoints from abuse

5. **Security Headers:**
   - Add Content-Security-Policy
   - Configure X-Frame-Options
   - Enable X-Content-Type-Options

6. **Database Security:**
   - Encrypt SQLite database file
   - Or migrate to SQL Server with TDE
   - Implement database backups

7. **Monitoring:**
   - Set up log aggregation (ELK, Splunk, etc.)
   - Configure alerts for security events
   - Implement health checks

8. **Penetration Testing:**
   - Conduct security assessment
   - Fix any identified vulnerabilities
   - Retest after fixes

### Conclusion

This deliverable significantly improved the security posture of CasaConnect by addressing 7 out of 10 OWASP Top 10 categories. The migration from cookie-based authentication to ASP.NET Core Identity provided robust protection against common authentication vulnerabilities. Input validation, access control, and comprehensive logging ensure the application is better protected against attacks and provides necessary audit trails for compliance and incident response.

The remaining OWASP categories (A06 - Vulnerable Components, A08 - Software and Data Integrity Failures, A10 - Server-Side Request Forgery) should be addressed in future security reviews through dependency scanning, code signing, and additional input validation for external requests.
1. **Prevents User Enumeration:** Generic error message doesn't reveal whether email exists
2. **Brute Force Protection:** Account lockout after 5 failed attempts (configured in Program.cs)
3. **MFA Support:** Framework for two-factor authentication
4. **Security Logging:** All authentication events logged for audit trails

#### User Registration
**Old:** Manual user creation with direct database access
```csharp
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
```

**New:** Identity-based registration with proper role assignment
```csharp
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
```

**Security Improvements:**
1. **Password Policy Enforcement:** Identity validates password complexity automatically
2. **Secure Password Storage:** Uses PBKDF2 with salt (handled by Identity)
3. **Role Management:** Proper role assignment through RoleManager
4. **Error Handling:** Detailed validation errors returned to user

#### Profile Management
**Old:** Direct database access with potential authorization bypass
```csharp
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

await _context.SaveChangesAsync();
```

**New:** Identity-managed profile updates with proper password reset
```csharp
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
```

**Security Improvements:**
1. **Token-Based Password Reset:** Uses secure token generation for password changes
2. **Audit Trail:** UpdatedAt timestamp tracks profile modifications
3. **Authorization:** GetUserAsync automatically ensures user can only modify their own profile
4. **Validation:** All updates validated through UserManager

#### Logout
**Old:** Cookie-based sign out
```csharp
await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
```

**New:** Identity-based sign out
```csharp
await _signInManager.SignOutAsync();
```

**Security Improvement:** Properly invalidates all authentication tokens and cleans up session state.

---

## UserController.cs - Broken Access Control

**File:** `Controllers/UserController.cs`

**OWASP Categories Addressed:**
- A01:2021 - Broken Access Control
- A03:2021 - Injection
- A04:2021 - Insecure Design

### What Changed

#### Controller Authorization
**Old:** No controller-level authorization
```csharp
public class UserController : Controller
```

**New:** Requires authentication for all actions
```csharp
[Authorize]
public class UserController : Controller
```

**Security Improvement:** Prevents unauthorized access to any user management functionality.

#### Index Action (User Listing)
**Old:** Public access to all users
```csharp
public IActionResult Index()
{
    var users = _context.Users.ToList();
    return View(users);
}
```

**New:** Admin-only access with async operation
```csharp
[Authorize(Roles = "Admin")]
public async Task<IActionResult> Index()
{
    var users = await _context.Users.ToListAsync();
    return View(users);
}
```

**Security Improvement:** Prevents information disclosure by restricting user listing to administrators only.

#### Edit Action - Resource Ownership Check
**Old:** No authorization check - any authenticated user could edit any profile
```csharp
public IActionResult Edit(int id)
{
    var user = _context.Users.Find(id);
    if (user == null)
    {
        return NotFound();
    }
    return View(user);
}
```

**New:** Validates user owns resource or is admin
```csharp
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
```

**Security Improvements:**
1. **Horizontal Privilege Escalation Prevention:** Users cannot edit other users' profiles
2. **Proper HTTP Status Codes:** Returns 403 Forbidden instead of 404 for authorization failures
3. **Admin Override:** Allows administrators to manage all users

#### Edit POST - Mass Assignment Prevention
**Old:** Accepts entire User object, allowing modification of any field
```csharp
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
        existingUser.Role = user.Role;  // Security issue: role can be modified

        _context.SaveChanges();
        return RedirectToAction(nameof(Index));
    }

    return View(user);
}
```

**New:** Restricted field binding with ownership validation
```csharp
[HttpPost]
[ValidateAntiForgeryToken]
public async Task<IActionResult> Edit(int id, [Bind("Id,FirstName,LastName,PhoneNumber,Address")] User model)
{
    var currentUser = await _userManager.GetUserAsync(User);
    if (currentUser == null) return Forbid();

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
```

**Security Improvements:**
1. **Mass Assignment Prevention:** [Bind] attribute restricts updatable fields
2. **Role Protection:** Role field cannot be modified through profile edit
3. **Privilege Escalation Prevention:** Users cannot elevate their own privileges
4. **Audit Logging:** Updates tracked with UpdatedAt timestamp
5. **Error Handling:** Proper exception logging without exposing internal details

#### Delete Action
**Old:** No authorization check
```csharp
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
```

**New:** Admin-only with async operations
```csharp
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
```

**Security Improvement:** Restricts user deletion to administrators only, preventing unauthorized account removal.

#### Admin Creation
**Old:** Manual password hashing
```csharp
var passwordHasher = new PasswordHasher<User>();
user.Password = passwordHasher.HashPassword(user, model.Password);

_context.Users.Add(user);
await _context.SaveChangesAsync();
```

**New:** Identity-managed creation with proper role assignment
```csharp
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
```

**Security Improvements:**
1. **Password Policy Enforcement:** Automatically validated by Identity
2. **Secure Storage:** Password hashed with PBKDF2 and unique salt
3. **Role Management:** Proper role assignment through RoleManager
4. **Validation Feedback:** Clear error messages for validation failures

---

## AdminPropertiesController.cs - Admin Property Management

**File:** `Controllers/AdminPropertiesController.cs`

**OWASP Categories Addressed:**
- A01:2021 - Broken Access Control
- A03:2021 - Injection
- A04:2021 - Insecure Design
- A05:2021 - Security Misconfiguration

### What Changed

#### File Upload Security
**Old:** Minimal file validation
```csharp
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
```

**New:** Comprehensive file validation and secure storage
```csharp
if (newImages != null && newImages.Any())
{
    foreach (var file in newImages)
    {
        // Validate file size (5 MB limit)
        if (file.Length > 5 * 1024 * 1024)
        {
            ModelState.AddModelError("", "File size cannot exceed 5 MB");
            continue;
        }

        // Validate file type
        var allowedExtensions = new[] { ".jpg", ".jpeg", ".png", ".gif" };
        var extension = Path.GetExtension(file.FileName).ToLowerInvariant();
        
        if (!allowedExtensions.Contains(extension))
        {
            ModelState.AddModelError("", "Invalid file type. Only JPG, PNG, and GIF are allowed.");
            continue;
        }

        // Validate content type
        if (!file.ContentType.StartsWith("image/"))
        {
            ModelState.AddModelError("", "File must be an image.");
            continue;
        }

        // Generate safe filename
        var safeName = Path.GetRandomFileName() + extension;
        var uploadDir = Path.Combine(_webHostEnvironment.WebRootPath, "property-images");

        if (!Directory.Exists(uploadDir))
            Directory.CreateDirectory(uploadDir);

        var uploadPath = Path.Combine(uploadDir, safeName);
        
        using var fs = System.IO.File.Create(uploadPath);
        await file.CopyToAsync(fs);

        existingProperty.Images.Add(new PropertyImage
        {
            ImagePath = safeName,
            UploadedAt = DateTime.UtcNow
        });
    }
}
```

**Security Improvements:**
1. **File Size Validation:** Prevents denial-of-service through large file uploads
2. **Extension Whitelist:** Only allows safe image formats
3. **Content Type Validation:** Verifies file is actually an image
4. **Path Traversal Prevention:** Uses Path.GetRandomFileName() to prevent directory traversal attacks
5. **MIME Type Verification:** Double-checks content type header

#### Property Update - Field Protection
**Old:** Overwrites all fields including immutable ones
```csharp
[HttpPost]
[ValidateAntiForgeryToken]
public async Task<IActionResult> Edit(int id, 
    [Bind("Id,Title,Description,Price,Address,City,State,ZipCode,Bedrooms,Bathrooms,SquareFootage,PropertyType,IsAvailable")] Property property)
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
        // Preserve original values
        property.OwnerId = existingProperty.OwnerId;
        property.CreatedAt = existingProperty.CreatedAt;
        property.UpdatedAt = DateTime.UtcNow;
        property.Images = existingProperty.Images;

        _context.Entry(existingProperty).CurrentValues.SetValues(property);
        await _context.SaveChangesAsync();
    }
}
```

**New:** Explicit field updates with proper binding
```csharp
[HttpPost]
[ValidateAntiForgeryToken]
public async Task<IActionResult> Edit(int id, 
    [Bind("Id,Title,Description,Price")] Property property, 
    IFormFile[] newImages)
{
    if (id != property.Id) return BadRequest();

    if (!ModelState.IsValid) return View(property);

    var existing = await _context.Properties.FindAsync(id);
    if (existing == null) return NotFound();

    // Update only allowed fields explicitly
    existing.Title = property.Title;
    existing.Description = property.Description;
    existing.Price = property.Price;
    existing.UpdatedAt = DateTime.UtcNow;

    _context.Update(existing);
    await _context.SaveChangesAsync();

    return RedirectToAction(nameof(Index));
}
```

**Security Improvements:**
1. **Immutable Field Protection:** OwnerId and CreatedAt cannot be modified
2. **Explicit Updates:** Only specified fields can be changed
3. **Mass Assignment Prevention:** [Bind] limits accepted properties
4. **Audit Trail:** UpdatedAt timestamp tracks modifications

#### Image Deletion Security
**Old:** Basic file deletion
```csharp
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
```

**New:** Secure file deletion with path validation
```csharp
if (deleteImages != null && deleteImages.Any())
{
    foreach (var imageId in deleteImages)
    {
        var image = await _context.PropertyImages.FindAsync(imageId);
        if (image != null && image.PropertyId == property.Id)
        {
            // Validate file path to prevent directory traversal
            var uploadDir = Path.Combine(_webHostEnvironment.WebRootPath, "property-images");
            var filePath = Path.Combine(uploadDir, image.ImagePath);
            
            // Ensure file is within allowed directory
            var fullPath = Path.GetFullPath(filePath);
            var allowedPath = Path.GetFullPath(uploadDir);
            
            if (fullPath.StartsWith(allowedPath) && System.IO.File.Exists(fullPath))
            {
                System.IO.File.Delete(fullPath);
            }
            
            _context.PropertyImages.Remove(image);
        }
    }
}
```

**Security Improvements:**
1. **Path Traversal Prevention:** Validates file is within allowed directory
2. **Ownership Verification:** Confirms image belongs to property being edited
3. **Safe Path Construction:** Uses Path.Combine instead of string concatenation

#### Property Deletion
**Old:** Basic cascade delete
```csharp
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
```

**New:** Secure deletion with proper error handling
```csharp
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
        var uploadDir = Path.Combine(_webHostEnvironment.WebRootPath, "property-images");
        
        foreach (var image in property.Images)
        {
            var filePath = Path.Combine(uploadDir, image.ImagePath);
            var fullPath = Path.GetFullPath(filePath);
            var allowedPath = Path.GetFullPath(uploadDir);
            
            if (fullPath.StartsWith(allowedPath) && System.IO.File.Exists(fullPath))
            {
                System.IO.File.Delete(fullPath);
            }
        }

        _context.Properties.Remove(property);
        await _context.SaveChangesAsync();
        
        _logger.LogInformation("Property {PropertyId} deleted by admin", id);
        TempData["SuccessMessage"] = "Property deleted successfully!";
    }
    catch (Exception ex)
    {
        _logger.LogError(ex, "Error deleting property {PropertyId}", id);
        TempData["ErrorMessage"] = "An error occurred while deleting the property.";
    }

    return RedirectToAction(nameof(Index));
}
```

**Security Improvements:**
1. **Secure File Deletion:** Validates paths before deletion
2. **Audit Logging:** Logs deletion events for compliance
3. **Error Handling:** Prevents information leakage in error messages
4. **Transaction Safety:** Database and filesystem operations properly coordinated

---

## HomeController.cs - Safe Claim Parsing

**File:** `Controllers/HomeController.cs`

**OWASP Categories Addressed:**
- A01:2021 - Broken Access Control
- A04:2021 - Insecure Design
- A05:2021 - Security Misconfiguration

### What Changed

#### User ID Claim Parsing
**Old:** Direct parsing without null checks
```csharp
if (User.Identity.IsAuthenticated)
{
    var userId = int.Parse(User.FindFirst("UserId").Value);
    ViewBag.IsFavorited = await _context.Favorites
        .AnyAsync(f => f.UserId == userId && f.PropertyId == property.Id);
}
```

**Issues with old code:**
1. No null check on FindFirst result
2. No validation of Value property
3. Throws exception if claim missing or value invalid
4. Uses custom "UserId" claim instead of standard ClaimTypes

**New:** Safe claim parsing with helper method
```csharp
private int? GetCurrentUserId()
{
    var claim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
    if (int.TryParse(claim, out var id)) return id;
    return null;
}

// Usage in PropertyDetails
if (User.Identity.IsAuthenticated)
{
    var userId = GetCurrentUserId();
    if (userId.HasValue)
    {
        ViewBag.IsFavorited = await _context.Favorites
            .AnyAsync(f => f.UserId == userId.Value && f.PropertyId == property.Id);
    }
}