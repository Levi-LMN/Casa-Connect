using CasaConnect.Data;
using CasaConnect.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace CasaConnect.Controllers
{
    [Authorize(Roles = "Owner")]
    public class PropertiesController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly IWebHostEnvironment _webHostEnvironment;

        public PropertiesController(ApplicationDbContext context, IWebHostEnvironment webHostEnvironment)
        {
            _context = context;
            _webHostEnvironment = webHostEnvironment;
        }

        // GET: Properties/Dashboard
        public async Task<IActionResult> Dashboard()
        {
            var userId = int.Parse(User.FindFirst("UserId").Value);
            var properties = await _context.Properties
                .Include(p => p.Images)
                .Where(p => p.OwnerId == userId)
                .ToListAsync();

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
        public async Task<IActionResult> Create([Bind("Title,Description,Price,Address,City,State,ZipCode,Bedrooms,Bathrooms,SquareFootage,PropertyType")] Property property, List<IFormFile>? images)
        {
            try
            {
                // Remove any model state errors for Owner and Images
                ModelState.Remove("Owner");
                ModelState.Remove("Images");

                if (ModelState.IsValid)
                {
                    // Set the OwnerId from the current user
                    property.OwnerId = int.Parse(User.FindFirst("UserId")?.Value ?? "0");
                    property.CreatedAt = DateTime.UtcNow;
                    property.IsAvailable = true;
                    property.Images = new List<PropertyImage>();

                    _context.Properties.Add(property);
                    await _context.SaveChangesAsync();

                    // Handle image uploads
                    if (images != null && images.Any())
                    {
                        var uploadPath = Path.Combine(_webHostEnvironment.WebRootPath, "property-images");
                        Directory.CreateDirectory(uploadPath);

                        foreach (var image in images)
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
                                    IsPrimary = !property.Images.Any(),
                                    UploadedAt = DateTime.UtcNow
                                };

                                _context.PropertyImages.Add(propertyImage);
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

            var userId = int.Parse(User.FindFirst("UserId").Value);
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
        public async Task<IActionResult> Edit(int id, [Bind("Id,Title,Description,Price,Address,City,State,ZipCode,Bedrooms,Bathrooms,SquareFootage,PropertyType,IsAvailable")] Property property, List<IFormFile>? newImages)
        {
            if (id != property.Id)
            {
                return NotFound();
            }

            var userId = int.Parse(User.FindFirst("UserId").Value);
            var existingProperty = await _context.Properties
                .Include(p => p.Images)
                .FirstOrDefaultAsync(p => p.Id == id && p.OwnerId == userId);

            if (existingProperty == null)
            {
                return NotFound();
            }

            if (ModelState.IsValid)
            {
                try
                {
                    // Preserve original owner and timestamps
                    property.OwnerId = existingProperty.OwnerId;
                    property.CreatedAt = existingProperty.CreatedAt;
                    property.UpdatedAt = DateTime.UtcNow;
                    property.Images = existingProperty.Images;

                    // Update the existing property values
                    _context.Entry(existingProperty).CurrentValues.SetValues(property);

                    // Handle image uploads
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
                    return RedirectToAction(nameof(Dashboard));
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
            }

            // If we get here, something failed. Reload the images before returning to the view
            property.Images = existingProperty.Images;
            return View(property);
        }

        private bool PropertyExists(int id)
        {
            return _context.Properties.Any(e => e.Id == id);
        }
    }
}