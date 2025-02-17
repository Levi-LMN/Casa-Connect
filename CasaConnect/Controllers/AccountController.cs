using CasaConnect.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity; // Add this namespace
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

public class AccountController : Controller
{
    private readonly CasaConnect.Data.ApplicationDbContext _context;
    private readonly IPasswordHasher<User> _passwordHasher; // Add password hasher

    public AccountController(CasaConnect.Data.ApplicationDbContext context, IPasswordHasher<User> passwordHasher)
    {
        _context = context;
        _passwordHasher = passwordHasher; // Inject the password hasher
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
            var user = _context.Users.FirstOrDefault(u =>
                u.Email == model.Email);

            if (user != null)
            {
                // Use PasswordHasher to verify the password
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
                // Use PasswordHasher to hash the password
                Password = _passwordHasher.HashPassword(new User(), model.Password),
                PhoneNo = model.PhoneNo,
                Address = model.Address,
                Role = model.Role, // Admin, Seeker, or Owner
                IsActive = true,
                CreatedAt = DateTime.UtcNow
            };

            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            // Automatically login after registration
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
        var userEmail = User.Identity.Name;
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

        // Verify this is the correct user
        if (user.Email != User.Identity.Name)
        {
            return Forbid();
        }

        user.FirstName = model.FirstName;
        user.LastName = model.LastName;
        user.PhoneNo = model.PhoneNo;
        user.Address = model.Address;

        // Optional: Handle password change
        if (!string.IsNullOrEmpty(model.NewPassword))
        {
            user.Password = _passwordHasher.HashPassword(user, model.NewPassword); // Hash the new password
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
