// ========================================
// HomeController.cs
// ========================================
// Purpose: Handles home page, property listings, and favorites
// OWASP Top 10 Security Implementations:
// - A01:2021 Broken Access Control: Authorization checks, user ownership validation
// - A03:2021 Injection: Parameterized queries via EF Core LINQ
// - A09:2021 Security Logging and Monitoring: Exception logging for errors
// - A04:2021 Insecure Design: Proper error handling without information disclosure

using CasaConnect.Data;
using CasaConnect.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace CasaConnect.Controllers
{
    public class HomeController : BaseController
    {
        private readonly ILogger<HomeController> _logger; // OWASP A09: Security logging
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
                // OWASP A03: Use parameterized LINQ queries (prevents SQL injection)
                var properties = await _context.Properties
                    .Include(p => p.Images)
                    .Include(p => p.Owner)
                    .Where(p => p.IsAvailable)
                    .OrderByDescending(p => p.CreatedAt)
                    .Take(12) // OWASP A04: Limit results to prevent resource exhaustion
                    .ToListAsync();

                return View(properties);
            }
            catch (Exception ex)
            {
                // OWASP A09: Log errors for monitoring
                // OWASP A04: Don't expose stack traces to users
                _logger.LogError(ex, "Error loading home page");
                return View(new List<Property>());
            }
        }

        public async Task<IActionResult> PropertyDetails(int? id)
        {
            // OWASP A03: Validate input parameter
            if (id == null)
            {
                return NotFound();
            }

            // OWASP A03: Parameterized query via EF Core
            var property = await _context.Properties
                .Include(p => p.Images)
                .Include(p => p.Owner)
                .FirstOrDefaultAsync(p => p.Id == id && p.IsAvailable);

            if (property == null)
            {
                return NotFound();
            }

            // OWASP A01: Check if property is favorited by current user
            // Only for authenticated users
            if (User.Identity.IsAuthenticated)
            {
                var userId = GetCurrentUserIdOrNull();
                if (userId.HasValue)
                {
                    // OWASP A03: Parameterized query
                    ViewBag.IsFavorited = await _context.Favorites
                        .AnyAsync(f => f.UserId == userId.Value && f.PropertyId == property.Id);
                }
            }

            return View(property);
        }

        [Authorize] // OWASP A01: Require authentication for favorite actions
        [HttpPost]
        public async Task<IActionResult> ToggleFavorite(int propertyId)
        {
            // OWASP A01: Get authenticated user ID
            var userId = GetCurrentUserId();

            // OWASP A03: Parameterized query to check existing favorite
            var favorite = await _context.Favorites
                .FirstOrDefaultAsync(f => f.UserId == userId && f.PropertyId == propertyId);

            if (favorite == null)
            {
                // OWASP A03: Parameterized insert
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
                // OWASP A03: Parameterized delete
                _context.Favorites.Remove(favorite);
                await _context.SaveChangesAsync();
                return Json(new { isFavorited = false });
            }
        }

        [Authorize] // OWASP A01: Require authentication
        public async Task<IActionResult> MyFavorites()
        {
            // OWASP A01: Get authenticated user ID
            var userId = GetCurrentUserId();

            // OWASP A03: Parameterized query - only show current user's favorites
            // OWASP A01: Users can only see their own favorites (horizontal privilege escalation prevention)
            var favorites = await _context.Favorites
                .Include(f => f.Property)
                .ThenInclude(p => p.Images)
                .Where(f => f.UserId == userId)
                .OrderByDescending(f => f.CreatedAt)
                .Select(f => f.Property)
                .ToListAsync();

            return View(favorites);
        }

        // Error page
        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            // OWASP A04: Generic error page without sensitive information
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