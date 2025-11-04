// Models/User.cs (updated to use ASP.NET Core Identity)
using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace CasaConnect.Models
{
    public class User : IdentityUser<int>
    {
        [Required]
        [StringLength(100)]
        [PersonalData] // Mark for GDPR/data protection
        public string FirstName { get; set; }

        [Required]
        [StringLength(100)]
        [PersonalData]
        public string LastName { get; set; }

        [StringLength(255)]
        [PersonalData]
        public string Address { get; set; }

        [Required]
        public string Role { get; set; } // Admin, Owner, Seeker

        public bool IsActive { get; set; } = true;

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        public DateTime? UpdatedAt { get; set; }

        // Navigation properties
        public virtual ICollection<Property> Properties { get; set; }
        public virtual ICollection<Favorite> Favorites { get; set; }

        // Password is now handled by IdentityUser - never stored in plaintext
        // Email and PhoneNumber are inherited from IdentityUser
    }
}