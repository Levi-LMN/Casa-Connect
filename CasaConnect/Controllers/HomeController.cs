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