// ========================================
// PropertiesController.cs
// ========================================
// Purpose: Property management for owners (CRUD operations)
// OWASP Top 10 Security Implementations:
// - A01:2021 Broken Access Control: Role-based auth, resource ownership validation
// - A03:2021 Injection: Parameterized queries, [Bind] attribute for mass assignment protection
// - A05:2021 Security Misconfiguration: ValidateAntiForgeryToken, secure file handling
// - A08:2021 Software and Data Integrity Failures: File type validation, secure filenames
// - A09:2021 Security Logging and Monitoring: Error logging and debugging

using CasaConnect.Data;
using CasaConnect.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace CasaConnect.Controllers
{
    [Authorize(Roles = "Owner")] // OWASP A01: Role-based access control - Owner only
    public class PropertiesController : BaseController
    {
        private readonly ApplicationDbContext _context;
        private readonly IWebHostEnvironment _webHostEnvironment;
        private readonly ILogger<PropertiesController> _logger; // OWASP A09: Security logging

        public PropertiesController(
            ApplicationDbContext context,
            IWebHostEnvironment webHostEnvironment,
            ILogger<PropertiesController> logger)
        {
            _context = context;
            _webHostEnvironment = webHostEnvironment;
            _logger = logger;
        }

        // GET: Properties/Dashboard
        public async Task<IActionResult> Dashboard()
        {
            // OWASP A01: Get authenticated user ID
            var userId = GetCurrentUserId();

            // OWASP A03: Parameterized query - only show owner's properties
            // OWASP A01: Horizontal privilege escalation prevention
            var properties = await _context.Properties
                .Include(p => p.Images)
                .Where(p => p.OwnerId == userId)
                .OrderByDescending(p => p.CreatedAt)
                .ToListAsync();

            // OWASP A09: Debug logging for image paths
            foreach (var property in properties)
            {
                if (property.Images != null)
                {
                    foreach (var image in property.Images)
                    {
                        _logger.LogInformation($"Property {property.Id}: Image path = {image.ImagePath}");
                    }
                }
            }

            return View(properties);
        }

        // GET: Properties/Create
        public IActionResult Create()
        {
            return View();
        }

        // POST: Properties/Create
        [HttpPost]
        [ValidateAntiForgeryToken] // OWASP A05: CSRF protection
        public async Task<IActionResult> Create(
            // OWASP A03: Mass assignment protection via [Bind] attribute
            [Bind("Title,Description,Price,Address,City,State,ZipCode,Bedrooms,Bathrooms,SquareFootage,PropertyType")] Property property,
            List<IFormFile>? images)
        {
            try
            {
                // Remove navigation properties from validation
                ModelState.Remove("Owner");
                ModelState.Remove("Images");

                // OWASP A03: Input validation
                if (ModelState.IsValid)
                {
                    // OWASP A01: Set owner to authenticated user (prevents property creation for other users)
                    property.OwnerId = GetCurrentUserId();
                    property.CreatedAt = DateTime.UtcNow;
                    property.IsAvailable = true;
                    property.Images = new List<PropertyImage>();

                    // OWASP A03: Parameterized insert via EF Core
                    _context.Properties.Add(property);
                    await _context.SaveChangesAsync();

                    // OWASP A08: Handle image uploads securely
                    if (images != null && images.Any())
                    {
                        var uploadPath = Path.Combine(_webHostEnvironment.WebRootPath, "property-images");

                        // OWASP A05: Ensure directory exists
                        if (!Directory.Exists(uploadPath))
                        {
                            Directory.CreateDirectory(uploadPath);
                            _logger.LogInformation($"Created directory: {uploadPath}");
                        }

                        bool isFirstImage = true;
                        foreach (var image in images)
                        {
                            if (image.Length > 0)
                            {
                                // OWASP A08: File type validation (whitelist approach)
                                var allowedExtensions = new[] { ".jpg", ".jpeg", ".png", ".gif", ".webp" };
                                var extension = Path.GetExtension(image.FileName).ToLowerInvariant();

                                if (!allowedExtensions.Contains(extension))
                                {
                                    _logger.LogWarning($"Invalid file type: {extension}");
                                    continue;
                                }

                                // OWASP A08: Generate unique, safe filename (prevents path traversal)
                                var fileName = Guid.NewGuid().ToString() + extension;
                                var filePath = Path.Combine(uploadPath, fileName);

                                // Save file securely
                                using (var stream = new FileStream(filePath, FileMode.Create))
                                {
                                    await image.CopyToAsync(stream);
                                }

                                // OWASP A03: Parameterized insert for image metadata
                                var propertyImage = new PropertyImage
                                {
                                    PropertyId = property.Id,
                                    ImagePath = "/property-images/" + fileName,
                                    IsPrimary = isFirstImage,
                                    UploadedAt = DateTime.UtcNow
                                };

                                _context.PropertyImages.Add(propertyImage);
                                isFirstImage = false;

                                // OWASP A09: Logging for audit trail
                                _logger.LogInformation($"Saved image: {propertyImage.ImagePath}");
                            }
                        }
                        await _context.SaveChangesAsync();
                    }

                    TempData["SuccessMessage"] = "Property created successfully!";
                    return RedirectToAction(nameof(Dashboard));
                }
                else
                {
                    // OWASP A09: Log validation errors
                    var errors = ModelState.Values.SelectMany(v => v.Errors)
                                                .Select(e => e.ErrorMessage)
                                                .ToList();
                    TempData["ErrorMessage"] = string.Join(", ", errors);
                }
            }
            catch (Exception ex)
            {
                // OWASP A09: Security logging for errors
                // OWASP A04: Don't expose internal details to user
                _logger.LogError(ex, "Error creating property");
                TempData["ErrorMessage"] = "An error occurred while saving the property: " + ex.Message;
            }

            return View(property);
        }

        // GET: Properties/Edit/5
        public async Task<IActionResult> Edit(int? id)
        {
            // OWASP A03: Validate input parameter
            if (id == null)
            {
                return NotFound();
            }

            // OWASP A01: Get authenticated user ID
            var userId = GetCurrentUserId();

            // OWASP A03: Parameterized query
            // OWASP A01: Verify user owns the property (horizontal privilege escalation prevention)
            var property = await _context.Properties
                .Include(p => p.Images)
                .FirstOrDefaultAsync(p => p.Id == id && p.OwnerId == userId);

            if (property == null)
            {
                return NotFound();
            }

            if (property.Images == null)
            {
                property.Images = new List<PropertyImage>();
            }

            return View(property);
        }

        // POST: Properties/Edit/5
        [HttpPost]
        [ValidateAntiForgeryToken] // OWASP A05: CSRF protection
        public async Task<IActionResult> Edit(
            int id,
            // OWASP A03: Mass assignment protection
            [Bind("Id,Title,Description,Price,Address,City,State,ZipCode,Bedrooms,Bathrooms,SquareFootage,PropertyType,IsAvailable")] Property property,
            List<IFormFile>? newImages,
            List<int>? deleteImages)
        {
            // OWASP A03: Validate ID matches
            if (id != property.Id)
            {
                return NotFound();
            }

            // OWASP A01: Get authenticated user ID
            var userId = GetCurrentUserId();

            // OWASP A03: Parameterized query
            // OWASP A01: Verify user owns the property before editing
            var existingProperty = await _context.Properties
                .Include(p => p.Images)
                .FirstOrDefaultAsync(p => p.Id == id && p.OwnerId == userId);

            if (existingProperty == null)
            {
                return NotFound();
            }

            try
            {
                // Remove navigation properties from validation
                ModelState.Remove("Owner");
                ModelState.Remove("Images");

                // OWASP A03: Input validation
                if (ModelState.IsValid)
                {
                    // OWASP A08: Handle image deletions
                    if (deleteImages != null && deleteImages.Any())
                    {
                        foreach (var imageId in deleteImages)
                        {
                            var image = await _context.PropertyImages.FindAsync(imageId);
                            // OWASP A01: Verify image belongs to this property
                            if (image != null && image.PropertyId == property.Id)
                            {
                                // OWASP A08: Delete physical file securely
                                var filePath = Path.Combine(_webHostEnvironment.WebRootPath, image.ImagePath.TrimStart('/'));
                                if (System.IO.File.Exists(filePath))
                                {
                                    System.IO.File.Delete(filePath);
                                    _logger.LogInformation($"Deleted image file: {filePath}");
                                }

                                _context.PropertyImages.Remove(image);
                            }
                        }
                        await _context.SaveChangesAsync();
                    }

                    // OWASP A01: Update only allowed fields (OwnerId cannot be changed - prevents property theft)
                    existingProperty.Title = property.Title;
                    existingProperty.Description = property.Description;
                    existingProperty.Price = property.Price;
                    existingProperty.Address = property.Address;
                    existingProperty.City = property.City;
                    existingProperty.State = property.State;
                    existingProperty.ZipCode = property.ZipCode;
                    existingProperty.Bedrooms = property.Bedrooms;
                    existingProperty.Bathrooms = property.Bathrooms;
                    existingProperty.SquareFootage = property.SquareFootage;
                    existingProperty.PropertyType = property.PropertyType;
                    existingProperty.IsAvailable = property.IsAvailable;
                    existingProperty.UpdatedAt = DateTime.UtcNow;

                    // OWASP A08: Handle new image uploads securely
                    if (newImages != null && newImages.Any())
                    {
                        var uploadPath = Path.Combine(_webHostEnvironment.WebRootPath, "property-images");

                        if (!Directory.Exists(uploadPath))
                        {
                            Directory.CreateDirectory(uploadPath);
                        }

                        foreach (var image in newImages)
                        {
                            if (image.Length > 0)
                            {
                                // OWASP A08: File type validation
                                var allowedExtensions = new[] { ".jpg", ".jpeg", ".png", ".gif", ".webp" };
                                var extension = Path.GetExtension(image.FileName).ToLowerInvariant();

                                if (!allowedExtensions.Contains(extension))
                                {
                                    continue;
                                }

                                // OWASP A08: Generate safe filename
                                var fileName = Guid.NewGuid().ToString() + extension;
                                var filePath = Path.Combine(uploadPath, fileName);

                                using (var stream = new FileStream(filePath, FileMode.Create))
                                {
                                    await image.CopyToAsync(stream);
                                }

                                var propertyImage = new PropertyImage
                                {
                                    PropertyId = property.Id,
                                    ImagePath = "/property-images/" + fileName,
                                    IsPrimary = existingProperty.Images == null || !existingProperty.Images.Any(),
                                    UploadedAt = DateTime.UtcNow
                                };

                                _context.PropertyImages.Add(propertyImage);
                            }
                        }
                    }

                    // OWASP A03: Parameterized update
                    await _context.SaveChangesAsync();
                    TempData["SuccessMessage"] = "Property updated successfully!";
                    return RedirectToAction(nameof(Dashboard));
                }
            }
            catch (DbUpdateConcurrencyException)
            {
                if (!PropertyExists(property.Id))
                {
                    return NotFound();
                }
                else
                {
                    throw;
                }
            }
            catch (Exception ex)
            {
                // OWASP A09: Security logging
                _logger.LogError(ex, "Error updating property");
                TempData["ErrorMessage"] = "An error occurred while updating the property: " + ex.Message;
            }

            // Reload images before returning to view
            property.Images = existingProperty.Images;
            return View(property);
        }

        // POST: Properties/DeleteImage/5
        [HttpPost]
        [ValidateAntiForgeryToken] // OWASP A05: CSRF protection
        public async Task<IActionResult> DeleteImage(int id)
        {
            // OWASP A01: Get authenticated user ID
            var userId = GetCurrentUserId();

            // OWASP A03: Parameterized query
            // OWASP A01: Verify user owns the property containing the image
            var image = await _context.PropertyImages
                .Include(pi => pi.Property)
                .FirstOrDefaultAsync(pi => pi.Id == id && pi.Property.OwnerId == userId);

            if (image == null)
            {
                return Json(new { success = false, message = "Image not found" });
            }

            try
            {
                // OWASP A08: Delete physical file securely
                var filePath = Path.Combine(_webHostEnvironment.WebRootPath, image.ImagePath.TrimStart('/'));
                if (System.IO.File.Exists(filePath))
                {
                    System.IO.File.Delete(filePath);
                }

                // OWASP A03: Parameterized delete
                _context.PropertyImages.Remove(image);
                await _context.SaveChangesAsync();

                return Json(new { success = true });
            }
            catch (Exception ex)
            {
                // OWASP A09: Security logging
                _logger.LogError(ex, "Error deleting image");
                return Json(new { success = false, message = ex.Message });
            }
        }

        // GET: Properties/Details/5
        public async Task<IActionResult> Details(int? id)
        {
            // OWASP A03: Validate input
            if (id == null)
            {
                return NotFound();
            }

            // OWASP A01: Get authenticated user ID
            var userId = GetCurrentUserId();

            // OWASP A03: Parameterized query
            // OWASP A01: Verify user owns the property
            var property = await _context.Properties
                .Include(p => p.Images)
                .Include(p => p.Owner)
                .FirstOrDefaultAsync(p => p.Id == id && p.OwnerId == userId);

            if (property == null)
            {
                return NotFound();
            }

            return View(property);
        }

        // GET: Properties/Delete/5
        public async Task<IActionResult> Delete(int? id)
        {
            // OWASP A03: Validate input
            if (id == null)
            {
                return NotFound();
            }

            // OWASP A01: Get authenticated user ID
            var userId = GetCurrentUserId();

            // OWASP A03: Parameterized query
            // OWASP A01: Verify user owns the property
            var property = await _context.Properties
                .Include(p => p.Images)
                .FirstOrDefaultAsync(p => p.Id == id && p.OwnerId == userId);

            if (property == null)
            {
                return NotFound();
            }

            return View(property);
        }

        // POST: Properties/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken] // OWASP A05: CSRF protection
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            // OWASP A01: Get authenticated user ID
            var userId = GetCurrentUserId();

            // OWASP A03: Parameterized query
            // OWASP A01: Verify user owns the property before deletion
            var property = await _context.Properties
                .Include(p => p.Images)
                .FirstOrDefaultAsync(p => p.Id == id && p.OwnerId == userId);

            if (property == null)
            {
                return NotFound();
            }

            try
            {
                // OWASP A08: Delete all property images from file system
                if (property.Images != null && property.Images.Any())
                {
                    foreach (var image in property.Images)
                    {
                        var filePath = Path.Combine(_webHostEnvironment.WebRootPath, image.ImagePath.TrimStart('/'));
                        if (System.IO.File.Exists(filePath))
                        {
                            System.IO.File.Delete(filePath);
                            _logger.LogInformation($"Deleted image file: {filePath}");
                        }
                    }
                }

                // OWASP A03: Parameterized delete (cascade deletes images via EF Core configuration)
                _context.Properties.Remove(property);
                await _context.SaveChangesAsync();

                TempData["SuccessMessage"] = "Property deleted successfully!";
                return RedirectToAction(nameof(Dashboard));
            }
            catch (Exception ex)
            {
                // OWASP A09: Security logging
                _logger.LogError(ex, "Error deleting property");
                TempData["ErrorMessage"] = "An error occurred while deleting the property: " + ex.Message;
                return RedirectToAction(nameof(Dashboard));
            }
        }

        private bool PropertyExists(int id)
        {
            return _context.Properties.Any(e => e.Id == id);
        }
    }
}