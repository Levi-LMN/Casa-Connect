// ========================================
// PropertiesController.cs - COMPLETE
// ========================================
using CasaConnect.Data;
using CasaConnect.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace CasaConnect.Controllers
{
    [Authorize(Roles = "Owner")]
    public class PropertiesController : BaseController
    {
        private readonly ApplicationDbContext _context;
        private readonly IWebHostEnvironment _webHostEnvironment;
        private readonly ILogger<PropertiesController> _logger;

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
            var userId = GetCurrentUserId();
            var properties = await _context.Properties
                .Include(p => p.Images)
                .Where(p => p.OwnerId == userId)
                .OrderByDescending(p => p.CreatedAt)
                .ToListAsync();

            // Log image paths for debugging
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
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(
            [Bind("Title,Description,Price,Address,City,State,ZipCode,Bedrooms,Bathrooms,SquareFootage,PropertyType")] Property property,
            List<IFormFile>? images)
        {
            try
            {
                ModelState.Remove("Owner");
                ModelState.Remove("Images");

                if (ModelState.IsValid)
                {
                    property.OwnerId = GetCurrentUserId();
                    property.CreatedAt = DateTime.UtcNow;
                    property.IsAvailable = true;
                    property.Images = new List<PropertyImage>();

                    _context.Properties.Add(property);
                    await _context.SaveChangesAsync();

                    // Handle image uploads
                    if (images != null && images.Any())
                    {
                        var uploadPath = Path.Combine(_webHostEnvironment.WebRootPath, "property-images");

                        // Ensure directory exists
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
                                // Validate file type
                                var allowedExtensions = new[] { ".jpg", ".jpeg", ".png", ".gif", ".webp" };
                                var extension = Path.GetExtension(image.FileName).ToLowerInvariant();

                                if (!allowedExtensions.Contains(extension))
                                {
                                    _logger.LogWarning($"Invalid file type: {extension}");
                                    continue;
                                }

                                // Generate unique filename
                                var fileName = Guid.NewGuid().ToString() + extension;
                                var filePath = Path.Combine(uploadPath, fileName);

                                // Save file
                                using (var stream = new FileStream(filePath, FileMode.Create))
                                {
                                    await image.CopyToAsync(stream);
                                }

                                // Create database entry
                                var propertyImage = new PropertyImage
                                {
                                    PropertyId = property.Id,
                                    ImagePath = "/property-images/" + fileName,
                                    IsPrimary = isFirstImage,
                                    UploadedAt = DateTime.UtcNow
                                };

                                _context.PropertyImages.Add(propertyImage);
                                isFirstImage = false;

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
                    var errors = ModelState.Values.SelectMany(v => v.Errors)
                                                .Select(e => e.ErrorMessage)
                                                .ToList();
                    TempData["ErrorMessage"] = string.Join(", ", errors);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating property");
                TempData["ErrorMessage"] = "An error occurred while saving the property: " + ex.Message;
            }

            return View(property);
        }

        // GET: Properties/Edit/5
        public async Task<IActionResult> Edit(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var userId = GetCurrentUserId();
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
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(
            int id,
            [Bind("Id,Title,Description,Price,Address,City,State,ZipCode,Bedrooms,Bathrooms,SquareFootage,PropertyType,IsAvailable")] Property property,
            List<IFormFile>? newImages,
            List<int>? deleteImages)
        {
            if (id != property.Id)
            {
                return NotFound();
            }

            var userId = GetCurrentUserId();
            var existingProperty = await _context.Properties
                .Include(p => p.Images)
                .FirstOrDefaultAsync(p => p.Id == id && p.OwnerId == userId);

            if (existingProperty == null)
            {
                return NotFound();
            }

            try
            {
                ModelState.Remove("Owner");
                ModelState.Remove("Images");

                if (ModelState.IsValid)
                {
                    // Handle image deletions
                    if (deleteImages != null && deleteImages.Any())
                    {
                        foreach (var imageId in deleteImages)
                        {
                            var image = await _context.PropertyImages.FindAsync(imageId);
                            if (image != null && image.PropertyId == property.Id)
                            {
                                // Delete physical file
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

                    // Update property values
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

                    // Handle new image uploads
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
                                var allowedExtensions = new[] { ".jpg", ".jpeg", ".png", ".gif", ".webp" };
                                var extension = Path.GetExtension(image.FileName).ToLowerInvariant();

                                if (!allowedExtensions.Contains(extension))
                                {
                                    continue;
                                }

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
                _logger.LogError(ex, "Error updating property");
                TempData["ErrorMessage"] = "An error occurred while updating the property: " + ex.Message;
            }

            // If we get here, something failed. Reload the images before returning to the view
            property.Images = existingProperty.Images;
            return View(property);
        }

        // POST: Properties/DeleteImage/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteImage(int id)
        {
            var userId = GetCurrentUserId();
            var image = await _context.PropertyImages
                .Include(pi => pi.Property)
                .FirstOrDefaultAsync(pi => pi.Id == id && pi.Property.OwnerId == userId);

            if (image == null)
            {
                return Json(new { success = false, message = "Image not found" });
            }

            try
            {
                // Delete physical file
                var filePath = Path.Combine(_webHostEnvironment.WebRootPath, image.ImagePath.TrimStart('/'));
                if (System.IO.File.Exists(filePath))
                {
                    System.IO.File.Delete(filePath);
                }

                _context.PropertyImages.Remove(image);
                await _context.SaveChangesAsync();

                return Json(new { success = true });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting image");
                return Json(new { success = false, message = ex.Message });
            }
        }

        // GET: Properties/Details/5
        public async Task<IActionResult> Details(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var userId = GetCurrentUserId();
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
            if (id == null)
            {
                return NotFound();
            }

            var userId = GetCurrentUserId();
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
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            var userId = GetCurrentUserId();
            var property = await _context.Properties
                .Include(p => p.Images)
                .FirstOrDefaultAsync(p => p.Id == id && p.OwnerId == userId);

            if (property == null)
            {
                return NotFound();
            }

            try
            {
                // Delete all property images from file system
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

                _context.Properties.Remove(property);
                await _context.SaveChangesAsync();

                TempData["SuccessMessage"] = "Property deleted successfully!";
                return RedirectToAction(nameof(Dashboard));
            }
            catch (Exception ex)
            {
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