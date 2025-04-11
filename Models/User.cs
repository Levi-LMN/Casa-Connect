using System.ComponentModel.DataAnnotations;

namespace CasaConnect.Models
{
    public class User
    {
        [Key]
        public int Id { get; set; }

        [Required]
        [StringLength(100)]
        public string FirstName { get; set; }

        [Required]
        [StringLength(100)]
        public string LastName { get; set; }

        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        public string Password { get; set; } // Ideally, store hashed passwords

        [StringLength(255)]
        public string Address { get; set; }

        [Required]
        public string Role { get; set; } // Admin, Owner, Seeker

        public bool IsActive { get; set; } = true;

        [Required]
        public string PhoneNo { get; set; }

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    }
}
