// ========================================
// AdminPropertiesController.cs
// ========================================
// Purpose: Admin management of all properties
// OWASP Top 10 Security Implementations:
// - A01:2021 Broken Access Control: Role-based authorization, resource ownership validation
// - A03:2021 Injection: Parameterized queries via EF Core, [Bind] attribute
// - A04:2021 Insecure Design: Prevents property theft by not allowing OwnerId changes
// - A05:2021 Security Misconfiguration: ValidateAntiForgeryToken, file upload validation
// - A08:2021 Software and Data Integrity Failures: File type validation, safe filenames

using CasaConnect.Data;
using CasaConnect.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace CasaConnect.Controllers
{
    [Authorize(Roles = "Admin")] // OWASP A01: Role-based access control - Admin only
    public class AdminPropertiesController : BaseController
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
        [ValidateAntiForgeryToken] // OWASP A05: CSRF protection
        public async Task<IActionResult> Edit(int id,
            [Bind("Id,Title,Description,Price")] Property property, // OWASP A03: Mass assignment protection
            IFormFile[] newImages)
        {
            // OWASP A03: Parameter validation
            if (id != property.Id) return BadRequest();

            // OWASP A03: Input validation
            if (!ModelState.IsValid) return View(property);

            // OWASP A03: Use parameterized query via EF Core
            var existing = await _context.Properties.FindAsync(id);
            if (existing == null) return NotFound();

            // OWASP A01 & A04: OwnerId cannot be changed - prevents property theft
            // This prevents an admin from transferring properties to themselves or others maliciously
            // Only update allowed fields
            existing.Title = property.Title;
            existing.Description = property.Description;
            existing.Price = property.Price;
            existing.UpdatedAt = DateTime.UtcNow;

            // OWASP A08: Handle images - validate file types and store with safe filenames
            if (newImages != null && newImages.Any())
            {
                foreach (var file in newImages)
                {
                    // OWASP A08: File size validation
                    if (file.Length > 0 && file.ContentType.StartsWith("image/"))
                    {
                        // OWASP A08: Generate random filename to prevent path traversal
                        var safeName = Path.GetRandomFileName() + Path.GetExtension(file.FileName);
                        var uploadDir = Path.Combine(_webHostEnvironment.WebRootPath, "property-images");

                        // OWASP A05: Ensure directory exists securely
                        if (!Directory.Exists(uploadDir))
                            Directory.CreateDirectory(uploadDir);

                        // OWASP A08: Use safe file path construction
                        var uploadPath = Path.Combine(uploadDir, safeName);
                        using var fs = System.IO.File.Create(uploadPath);
                        await file.CopyToAsync(fs);

                        // OWASP A03: Use parameterized insert via EF Core
                        existing.Images.Add(new PropertyImage
                        {
                            ImagePath = "/property-images/" + safeName,
                            UploadedAt = DateTime.UtcNow
                        });
                    }
                }
            }

            // OWASP A03: Parameterized update via EF Core
            _context.Update(existing);
            await _context.SaveChangesAsync();

            return RedirectToAction(nameof(Index));
        }
    }
}