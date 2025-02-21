namespace CasaConnect.Models
{
    public class Favorite
    {
        public int Id { get; set; }
        public int UserId { get; set; }
        public int PropertyId { get; set; }
        public DateTime CreatedAt { get; set; }

        // Navigation properties
        public virtual User User { get; set; }  // Changed from ApplicationUser to User
        public virtual Property Property { get; set; }
    }
}