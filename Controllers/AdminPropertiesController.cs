using CasaConnect.Data;
using CasaConnect.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

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

    // Example: Edit action - validate model and handle files safely
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Edit(int id, [Bind("Id,Title,Description,Price")] Property property, IFormFile[] newImages)
    {
        if (id != property.Id) return BadRequest();

        if (!ModelState.IsValid) return View(property);

        var existing = await _context.Properties.FindAsync(id);
        if (existing == null) return NotFound();

        existing.Title = property.Title;
        existing.Description = property.Description;
        existing.Price = property.Price;
        existing.UpdatedAt = DateTime.UtcNow;

        // Handle images - validate file types and store with safe filenames
        if (newImages != null && newImages.Any())
        {
            foreach (var file in newImages)
            {
                if (file.Length > 0 && file.ContentType.StartsWith("image/"))
                {
                    var safeName = Path.GetRandomFileName() + Path.GetExtension(file.FileName);
                    var uploadDir = Path.Combine(_webHostEnvironment.WebRootPath, "property-images");

                    if (!Directory.Exists(uploadDir))
                        Directory.CreateDirectory(uploadDir);

                    var uploadPath = Path.Combine(uploadDir, safeName);
                    using var fs = System.IO.File.Create(uploadPath);
                    await file.CopyToAsync(fs);

                    existing.Images.Add(new PropertyImage
                    {
                        ImagePath = safeName,
                        UploadedAt = DateTime.UtcNow
                    });
                }
            }
        }

        _context.Update(existing);
        await _context.SaveChangesAsync();

        return RedirectToAction(nameof(Index));
    }
}
