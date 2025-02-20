using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace CasaConnect.Models
{
    public class Conversation
    {
        public int Id { get; set; }

        [Required]
        public int PropertyId { get; set; }

        [Required]
        public int SeekerId { get; set; }

        [Required]
        public int OwnerId { get; set; }

        public DateTime CreatedAt { get; set; }
        public DateTime? LastMessageAt { get; set; }

        [ForeignKey("PropertyId")]
        public virtual Property Property { get; set; }

        [ForeignKey("SeekerId")]
        public virtual User Seeker { get; set; }

        [ForeignKey("OwnerId")]
        public virtual User Owner { get; set; }

        public virtual ICollection<Message> Messages { get; set; }
    }
}