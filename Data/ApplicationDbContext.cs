using CasaConnect.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace CasaConnect.Data
{
    // Updated to use Identity with int keys for both User and Role
    public class ApplicationDbContext : IdentityDbContext<User, ApplicationRole, int>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        // Your existing DbSets
        public DbSet<Property> Properties { get; set; }
        public DbSet<PropertyImage> PropertyImages { get; set; }
        public DbSet<Message> Messages { get; set; }
        public DbSet<Conversation> Conversations { get; set; }
        public DbSet<Favorite> Favorites { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            // User entity configuration (additional to Identity defaults)
            modelBuilder.Entity<User>(entity =>
            {
                entity.Property(u => u.FirstName).IsRequired().HasMaxLength(100);
                entity.Property(u => u.LastName).IsRequired().HasMaxLength(100);
                entity.Property(u => u.Address).HasMaxLength(255);
                entity.Property(u => u.Role).IsRequired();
                entity.Property(u => u.IsActive).HasDefaultValue(true);
                entity.Property(u => u.CreatedAt).IsRequired();
            });

            // Property entity configuration
            modelBuilder.Entity<Property>(entity =>
            {
                entity.HasKey(p => p.Id);
                entity.Property(p => p.Title).IsRequired().HasMaxLength(200);
                entity.Property(p => p.Description).HasMaxLength(1000);
                entity.Property(p => p.Price).HasColumnType("decimal(18,2)");

                // Property belongs to one User (Owner)
                entity.HasOne(p => p.Owner)
                    .WithMany(u => u.Properties)
                    .HasForeignKey(p => p.OwnerId)
                    .OnDelete(DeleteBehavior.Cascade);

                // ✅ FIXED: Explicitly configure Images relationship
                entity.HasMany(p => p.Images)
                    .WithOne(pi => pi.Property)
                    .HasForeignKey(pi => pi.PropertyId)
                    .OnDelete(DeleteBehavior.Cascade);
            });

            // PropertyImage entity configuration
            modelBuilder.Entity<PropertyImage>(entity =>
            {
                entity.HasKey(pi => pi.Id);
                entity.Property(pi => pi.ImagePath).IsRequired();
                entity.Property(pi => pi.UploadedAt).IsRequired();

                // ✅ FIXED: Configure the inverse relationship
                entity.HasOne(pi => pi.Property)
                    .WithMany(p => p.Images)  // ✅ Must match the Property.Images property
                    .HasForeignKey(pi => pi.PropertyId)
                    .IsRequired()
                    .OnDelete(DeleteBehavior.Cascade);
            });

            // Message entity configuration
            modelBuilder.Entity<Message>(entity =>
            {
                entity.HasKey(m => m.Id);
                entity.Property(m => m.Content).IsRequired().HasMaxLength(1000);
                entity.Property(m => m.SentAt).IsRequired();

                // Configure Sender relationship
                entity.HasOne(m => m.Sender)
                    .WithMany()
                    .HasForeignKey(m => m.SenderId)
                    .OnDelete(DeleteBehavior.Restrict);

                // Configure Receiver relationship
                entity.HasOne(m => m.Receiver)
                    .WithMany()
                    .HasForeignKey(m => m.ReceiverId)
                    .OnDelete(DeleteBehavior.Restrict);

                // Configure Conversation relationship
                entity.HasOne(m => m.Conversation)
                    .WithMany(c => c.Messages)
                    .HasForeignKey(m => m.ConversationId)
                    .OnDelete(DeleteBehavior.Cascade);
            });

            // Conversation entity configuration
            modelBuilder.Entity<Conversation>(entity =>
            {
                entity.HasKey(c => c.Id);

                // Configure Seeker relationship
                entity.HasOne(c => c.Seeker)
                    .WithMany()
                    .HasForeignKey(c => c.SeekerId)
                    .OnDelete(DeleteBehavior.Restrict);

                // Configure Owner relationship
                entity.HasOne(c => c.Owner)
                    .WithMany()
                    .HasForeignKey(c => c.OwnerId)
                    .OnDelete(DeleteBehavior.Restrict);

                // Messages relationship (already configured above)
                entity.HasMany(c => c.Messages)
                    .WithOne(m => m.Conversation)
                    .HasForeignKey(m => m.ConversationId)
                    .OnDelete(DeleteBehavior.Cascade);
            });

            // Favorite entity configuration
            modelBuilder.Entity<Favorite>(entity =>
            {
                entity.HasKey(f => f.Id);

                // Composite unique index to prevent duplicate favorites
                entity.HasIndex(f => new { f.UserId, f.PropertyId }).IsUnique();

                // Favorite belongs to one User
                entity.HasOne(f => f.User)
                    .WithMany(u => u.Favorites)
                    .HasForeignKey(f => f.UserId)
                    .OnDelete(DeleteBehavior.Cascade);

                // Favorite belongs to one Property
                entity.HasOne(f => f.Property)
                    .WithMany()
                    .HasForeignKey(f => f.PropertyId)
                    .OnDelete(DeleteBehavior.Restrict); // Changed to Restrict to prevent cascade conflicts
            });
        }
    }
}