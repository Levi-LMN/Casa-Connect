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