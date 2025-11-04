// UserController.cs
// Purpose: User management and profile editing
// OWASP Top 10 Security Implementations:
// - A01:2021 Broken Access Control: Resource ownership validation, role-based authorization
// - A02:2021 Cryptographic Failures: Password handling via Identity
// - A03:2021 Injection: Parameterized queries, [Bind] attribute
// - A05:2021 Security Misconfiguration: ValidateAntiForgeryToken
// - A09:2021 Security Logging and Monitoring: Error logging

using CasaConnect.Data;
using CasaConnect.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace CasaConnect.Controllers
{
    [Authorize] // OWASP A01: Require authentication for all actions
    public class UserController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly UserManager<User> _userManager;
        private readonly ILogger<UserController> _logger; // OWASP A09: Security logging

        public UserController(ApplicationDbContext context, UserManager<User> userManager, ILogger<UserController> logger)
        {
            _context = context;
            _userManager = userManager;
            _logger = logger;
        }

        [Authorize(Roles = "Admin")] // OWASP A01: Role-based access control - Admin only
        public async Task<IActionResult> Index()
        {
            // OWASP A03: Parameterized query via EF Core
            var users = await _context.Users.ToListAsync();
            return View(users);
        }

        // GET: User/Edit/5
        [HttpGet]
        public async Task<IActionResult> Edit(int id)
        {
            // OWASP A01: Get current authenticated user
            var currentUser = await _userManager.GetUserAsync(User);
            if (currentUser == null) return Forbid();

            // OWASP A01: Check resource ownership - prevent horizontal privilege escalation
            // Users can only edit their own profile OR admin can edit any profile
            if (currentUser.Id != id && !User.IsInRole("Admin"))
            {
                return Forbid();
            }

            // OWASP A03: Parameterized query
            var user = await _context.Users.FindAsync(id);
            if (user == null) return NotFound();

            return View(user);
        }

        [HttpPost]
        [ValidateAntiForgeryToken] // OWASP A05: CSRF protection
        public async Task<IActionResult> Edit(int id,
            [Bind("Id,FirstName,LastName,PhoneNumber,Address")] User model) // OWASP A03: Mass assignment protection
        {
            // OWASP A01: Get current authenticated user
            var currentUser = await _userManager.GetUserAsync(User);
            if (currentUser == null) return Forbid();

            // OWASP A01: Verify resource ownership or admin privilege
            if (currentUser.Id != id && !User.IsInRole("Admin"))
            {
                return Forbid();
            }

            // OWASP A03: Input validation
            if (!ModelState.IsValid) return View(model);

            // OWASP A03: Parameterized query
            var user = await _context.Users.FindAsync(id);
            if (user == null) return NotFound();

            // OWASP A01: Update only allowed fields (prevents privilege escalation)
            // Role, Email, and Password fields are NOT updated here
            user.FirstName = model.FirstName;
            user.LastName = model.LastName;
            user.PhoneNumber = model.PhoneNumber;
            user.Address = model.Address;
            user.UpdatedAt = DateTime.UtcNow;

            try
            {
                // OWASP A03: Parameterized update via EF Core
                _context.Update(user);
                await _context.SaveChangesAsync();
                TempData["SuccessMessage"] = "User updated successfully!";
                return RedirectToAction(nameof(Index));
            }
            catch (DbUpdateException ex)
            {
                // OWASP A09: Security logging for database errors
                _logger.LogError(ex, "Error updating user {UserId}", id);
                ModelState.AddModelError("", "Unable to save changes. Try again.");
                return View(model);
            }
        }

        // GET: User/Delete/5
        [Authorize(Roles = "Admin")] // OWASP A01: Admin-only action
        public async Task<IActionResult> Delete(int id)
        {
            // OWASP A03: Parameterized query
            var user = await _context.Users.FindAsync(id);
            if (user == null)
            {
                return NotFound();
            }
            return View(user);
        }

        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken] // OWASP A05: CSRF protection
        [Authorize(Roles = "Admin")] // OWASP A01: Admin-only action
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            // OWASP A03: Parameterized query
            var user = await _context.Users.FindAsync(id);
            if (user != null)
            {
                // OWASP A03: Parameterized delete (cascade deletes handled by EF Core)
                _context.Users.Remove(user);
                await _context.SaveChangesAsync();
                TempData["SuccessMessage"] = "User deleted successfully!";
            }
            return RedirectToAction(nameof(Index));
        }

        [Authorize(Roles = "Admin")] // OWASP A01: Admin-only action
        [HttpGet]
        public IActionResult CreateAdmin()
        {
            return View();
        }

        [HttpPost]
        [Authorize(Roles = "Admin")] // OWASP A01: Admin-only action
        [ValidateAntiForgeryToken] // OWASP A05: CSRF protection
        public async Task<IActionResult> CreateAdmin(RegisterViewModel model)
        {
            // OWASP A03: Input validation
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            // OWASP A07: Prevent duplicate accounts
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
                Role = "Admin", // OWASP A01: Force Admin role (not from user input)
                IsActive = true,
                CreatedAt = DateTime.UtcNow
            };

            // OWASP A02: Password hashing via Identity (PBKDF2)
            var result = await _userManager.CreateAsync(user, model.Password);
            if (result.Succeeded)
            {
                // OWASP A01: Assign Admin role
                await _userManager.AddToRoleAsync(user, "Admin");
                TempData["SuccessMessage"] = "Admin user created successfully!";
                return RedirectToAction(nameof(Index));
            }

            // Display Identity errors
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError("", error.Description);
            }

            return View(model);
        }
    }
}