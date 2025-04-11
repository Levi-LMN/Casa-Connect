using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace CasaConnect.Models
{
    public class Conversation
    {
        // Primary Key: Unique identifier for the conversation
        public int Id { get; set; }

        // Foreign Key: Links the conversation to a specific property
        [Required]
        public int PropertyId { get; set; }

        // Foreign Key: Links the conversation to the seeker (user looking for a property)
        [Required]
        public int SeekerId { get; set; }

        // Foreign Key: Links the conversation to the owner (user who owns the property)
        [Required]
        public int OwnerId { get; set; }

        // Timestamp when the conversation was created
        public DateTime CreatedAt { get; set; }

        // Timestamp of the last message sent (nullable, as there may be no messages yet)
        public DateTime? LastMessageAt { get; set; }

        // Navigation Property: Links to the associated Property entity
        [ForeignKey("PropertyId")]
        public virtual Property Property { get; set; }

        // Navigation Property: Links to the seeker (User entity)
        [ForeignKey("SeekerId")]
        public virtual User Seeker { get; set; }

        // Navigation Property: Links to the owner (User entity)
        [ForeignKey("OwnerId")]
        public virtual User Owner { get; set; }

        // Navigation Property: A collection of messages exchanged in this conversation
        public virtual ICollection<Message> Messages { get; set; }
    }
}
