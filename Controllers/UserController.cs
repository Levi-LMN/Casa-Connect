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