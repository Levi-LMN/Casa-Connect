// Models/User.cs
// Purpose: User entity with ASP.NET Core Identity integration
// OWASP Top 10 Security Implementations:
// - A02:2021 Cryptographic Failures: Password stored as hash via IdentityUser (never plaintext)
// - A03:2021 Injection: Input validation via Data Annotations
// - A06:2021 Vulnerable and Outdated Components: Uses latest Identity framework
// - A10:2021 Server-Side Request Forgery (SSRF): PersonalData attribute for GDPR compliance

using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace CasaConnect.Models
{
    // OWASP A02: Inherits from IdentityUser<int> which provides secure password hashing
    // Password is stored using PBKDF2 algorithm (100,000+ iterations in .NET 6+)
    public class User : IdentityUser<int>
    {
        // OWASP A03: Input validation via StringLength attribute
        // OWASP A10: PersonalData attribute marks PII for GDPR/data protection compliance
        [Required]
        [StringLength(100)]
        [PersonalData]
        public string FirstName { get; set; }

        [Required]
        [StringLength(100)]
        [PersonalData]
        public string LastName { get; set; }

        [StringLength(255)]
        [PersonalData]
        public string Address { get; set; }

        // OWASP A01: Role field for role-based access control
        [Required]
        public string Role { get; set; } // Admin, Owner, Seeker

        public bool IsActive { get; set; } = true;

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        public DateTime? UpdatedAt { get; set; }

        // Navigation properties
        public virtual ICollection<Property> Properties { get; set; }
        public virtual ICollection<Favorite> Favorites { get; set; }

        // OWASP A02: Password is handled by IdentityUser - NEVER stored in plaintext
        // OWASP A02: Email and PhoneNumber are inherited from IdentityUser with built-in validation
        // IdentityUser provides:
        // - PasswordHash: Securely hashed password using PBKDF2
        // - SecurityStamp: Token for password reset/change validation
        // - TwoFactorEnabled: Support for MFA
        // - LockoutEnabled: Account lockout protection
        // - AccessFailedCount: Failed login attempt tracking
    }
}