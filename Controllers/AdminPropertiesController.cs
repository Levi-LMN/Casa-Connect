using CasaConnect.Data;
using CasaConnect.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace CasaConnect.Controllers
{
    [Authorize(Roles = "Admin")]
    public class AdminPropertiesController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly IWebHostEnvironment _webHostEnvironment;

        public AdminPropertiesController(ApplicationDbContext context, IWebHostEnvironment webHostEnvironment)
        {
            _context = context;
            _webHostEnvironment = webHostEnvironment;
        }

        // GET: AdminProperties
        public async Task<IActionResult> Index()
        {
            var properties = await _context.Properties
                .Include(p => p.Owner)
                .Include(p => p.Images)
                .OrderByDescending(p => p.CreatedAt)
                .ToListAsync();

            return View(properties);
        }

        // GET: AdminProperties/Edit/5
        public async Task<IActionResult> Edit(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var property = await _context.Properties
                .Include(p => p.Owner)
                .Include(p => p.Images)
                .FirstOrDefaultAsync(p => p.Id == id);

            if (property == null)
            {
                return NotFound();
            }

            return View(property);
        }

        // POST: AdminProperties/Edit/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, [Bind("Id,Title,Description,Price,Address,City,State,ZipCode,Bedrooms,Bathrooms,SquareFootage,PropertyType,IsAvailable")] Property property, List<IFormFile>? newImages, List<int>? deleteImages)
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
                try
                {
                    // Handle image deletions
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

                    // Preserve original values
                    property.OwnerId = existingProperty.OwnerId;
                    property.CreatedAt = existingProperty.CreatedAt;
                    property.UpdatedAt = DateTime.UtcNow;
                    property.Images = existingProperty.Images;

                    _context.Entry(existingProperty).CurrentValues.SetValues(property);

                    // Handle new image uploads
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

                    await _context.SaveChangesAsync();
                    TempData["SuccessMessage"] = "Property updated successfully!";
                    return RedirectToAction(nameof(Index));
                }
                catch (Exception ex)
                {
                    TempData["ErrorMessage"] = "An error occurred while updating the property: " + ex.Message;
                }
            }

            property.Images = existingProperty.Images;
            return View(property);
        }

        // GET: AdminProperties/Details/5
        public async Task<IActionResult> Details(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var property = await _context.Properties
                .Include(p => p.Owner)
                .Include(p => p.Images)
                .FirstOrDefaultAsync(p => p.Id == id);

            if (property == null)
            {
                return NotFound();
            }

            return View(property);
        }

        // POST: AdminProperties/Delete/5
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
                // Delete all associated images
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
    }
}