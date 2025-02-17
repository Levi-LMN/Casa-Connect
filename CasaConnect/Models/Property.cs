using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace CasaConnect.Models
{
    public class Property
    {
        public int Id { get; set; }

        [Required]
        public string Title { get; set; }

        [Required]
        public string Description { get; set; }

        [Required]
        [Column(TypeName = "decimal(18,2)")]
        public decimal Price { get; set; }

        [Required]
        public string Address { get; set; }

        public string City { get; set; }
        public string State { get; set; }
        public string ZipCode { get; set; }

        [Required]
        public int Bedrooms { get; set; }

        [Required]
        public int Bathrooms { get; set; }

        public decimal SquareFootage { get; set; }

        public string PropertyType { get; set; }

        public bool IsAvailable { get; set; }

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime? UpdatedAt { get; set; }

        public int OwnerId { get; set; } // Foreign key

        [ForeignKey("OwnerId")]
        public virtual User? Owner { get; set; }  // Nullable to prevent errors if owner is not assigned

        public virtual List<PropertyImage>? Images { get; set; }  // Nullable list of property images
    }
}
