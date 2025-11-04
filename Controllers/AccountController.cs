// AccountController.cs
// Purpose: Handles user authentication, registration, profile management, and secure sign-in
// OWASP Top 10 Security Implementations:
// - A01:2021 Broken Access Control: [Authorize] attributes, user context validation
// - A02:2021 Cryptographic Failures: Password hashing via Identity (PBKDF2)
// - A03:2021 Injection: Parameterized queries via EF Core, input validation
// - A04:2021 Insecure Design: Account lockout, MFA stub, secure password policies
// - A05:2021 Security Misconfiguration: ValidateAntiForgeryToken, secure defaults
// - A07:2021 Identification and Authentication Failures: Identity framework, lockout protection
// - A09:2021 Security Logging and Monitoring: ILogger audit trails for auth events

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
        private readonly ILogger<AccountController> _logger; // OWASP A09: Security logging

        public AccountController(ApplicationDbContext context, SignInManager<User> signInManager,
            UserManager<User> userManager, ILogger<AccountController> logger)
        {
            _context = context;
            _signInManager = signInManager;
            _userManager = userManager;
            _logger = logger;
        }

        // GET: Login page
        [HttpGet]
        public IActionResult Login()
        {
            return View();
        }

        // POST: Handle login with security measures
        [HttpPost]
        [ValidateAntiForgeryToken] // OWASP A05: CSRF protection
        public async Task<IActionResult> Login(LoginViewModel model)
        {
            // OWASP A03: Input validation via ModelState
            if (!ModelState.IsValid) return View(model);

            // OWASP A07: User enumeration prevention - generic error messages
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                return View(model);
            }

            // OWASP A02: Secure password verification using Identity's hash comparison
            // OWASP A07: Account lockout protection against brute force
            var result = await _signInManager.PasswordSignInAsync(user, model.Password,
                model.RememberMe, lockoutOnFailure: true);

            if (result.Succeeded)
            {
                // OWASP A09: Audit logging for successful authentication
                _logger.LogInformation("User {UserId} logged in", user.Id);
                return RedirectToAction("Index", "Home");
            }
            if (result.RequiresTwoFactor)
            {
                // OWASP A07: MFA implementation (stub for 2FA)
                return RedirectToAction(nameof(VerifyTwoFactor));
            }
            if (result.IsLockedOut)
            {
                // OWASP A09: Security logging for lockout events
                _logger.LogWarning("User {Email} account locked out", model.Email);
                ModelState.AddModelError(string.Empty, "Account locked due to multiple failed login attempts.");
                return View(model);
            }

            // OWASP A07: Generic error to prevent user enumeration
            ModelState.AddModelError(string.Empty, "Invalid login attempt.");
            return View(model);
        }

        // GET: Registration page
        [HttpGet]
        public IActionResult Register()
        {
            return View();
        }

        // POST: Handle registration securely
        [HttpPost]
        [ValidateAntiForgeryToken] // OWASP A05: CSRF protection
        public async Task<IActionResult> Register(RegisterViewModel model)
        {
            // OWASP A03: Input validation
            if (!ModelState.IsValid) return View(model);

            // OWASP A07: Prevent duplicate accounts
            var existingUser = await _userManager.FindByEmailAsync(model.Email);
            if (existingUser != null)
            {
                ModelState.AddModelError("Email", "Email already exists");
                return View(model);
            }

            // Create new user instance
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

            // OWASP A02: Password hashing using PBKDF2 via Identity
            // OWASP A07: Strong password policy enforced by Identity configuration
            var result = await _userManager.CreateAsync(user, model.Password);
            if (result.Succeeded)
            {
                // OWASP A01: Role-based access control assignment
                await _userManager.AddToRoleAsync(user, model.Role);
                await _signInManager.SignInAsync(user, isPersistent: false);
                return RedirectToAction("Index", "Home");
            }

            // Display Identity errors
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            return View(model);
        }

        // POST: Logout user securely
        [HttpPost]
        [ValidateAntiForgeryToken] // OWASP A05: CSRF protection
        public async Task<IActionResult> Logout()
        {
            // OWASP A07: Proper session termination
            await _signInManager.SignOutAsync();
            return RedirectToAction("Login");
        }

        // GET: Profile page (requires authentication)
        [Authorize] // OWASP A01: Access control - authenticated users only
        [HttpGet]
        public async Task<IActionResult> Profile()
        {
            // OWASP A01: Validate user context
            var user = await _userManager.GetUserAsync(User);
            if (user == null) return NotFound();

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

        // POST: Update profile securely
        [Authorize] // OWASP A01: Access control
        [HttpPost]
        [ValidateAntiForgeryToken] // OWASP A05: CSRF protection
        public async Task<IActionResult> Profile(ProfileViewModel model)
        {
            // OWASP A03: Input validation
            if (!ModelState.IsValid) return View(model);

            // OWASP A01: Verify user owns the resource
            var user = await _userManager.GetUserAsync(User);
            if (user == null) return NotFound();

            // OWASP A01: Update only allowed fields to prevent privilege escalation
            // Role field is NOT updated here - prevents horizontal privilege escalation
            user.FirstName = model.FirstName;
            user.LastName = model.LastName;
            user.PhoneNumber = model.PhoneNo;
            user.Address = model.Address;
            user.UpdatedAt = DateTime.UtcNow;

            // OWASP A03: Parameterized updates via Identity
            var result = await _userManager.UpdateAsync(user);
            if (!result.Succeeded)
            {
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
                return View(model);
            }

            // OWASP A02: Secure password change with token validation
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

        // OWASP A07: MFA verification stub (implement with authenticator or SMS provider)
        [HttpGet]
        public IActionResult VerifyTwoFactor() => View();
    }
}