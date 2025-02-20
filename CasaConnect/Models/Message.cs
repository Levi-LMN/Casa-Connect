using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace CasaConnect.Models
{
    public class Message
    {
        public int Id { get; set; }

        [Required]
        public int SenderId { get; set; }

        [Required]
        public int ReceiverId { get; set; }

        [Required]
        public int PropertyId { get; set; }

        [Required]
        public int ConversationId { get; set; }

        [Required]
        [StringLength(1000)]
        public string Content { get; set; }

        public DateTime SentAt { get; set; }
        public DateTime? ReadAt { get; set; }

        [ForeignKey("SenderId")]
        public virtual User Sender { get; set; }

        [ForeignKey("ReceiverId")]
        public virtual User Receiver { get; set; }

        [ForeignKey("PropertyId")]
        public virtual Property Property { get; set; }

        [ForeignKey("ConversationId")]
        public virtual Conversation Conversation { get; set; }
    }
}