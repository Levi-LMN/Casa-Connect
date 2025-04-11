using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace CasaConnect.Models
{
    public class PropertyImage
    {
        public int Id { get; set; }

        public int PropertyId { get; set; }

        [Required]
        public string ImagePath { get; set; }

        public bool IsPrimary { get; set; }

        public DateTime UploadedAt { get; set; }

        [ForeignKey("PropertyId")]
        public virtual Property? Property { get; set; }
    }
}