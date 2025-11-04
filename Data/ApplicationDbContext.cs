// ApplicationDbContext.cs
// Purpose: Database context with secure entity configurations
// OWASP Top 10 Security Implementations:
// - A03:2021 Injection: Entity Framework Core provides parameterized queries by default
// - A04:2021 Insecure Design: Proper foreign key constraints and cascade delete policies
// - A01:2021 Broken Access Control: Database-level constraints enforce data integrity

using CasaConnect.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace CasaConnect.Data
{
    // OWASP A02 & A06: Uses Identity framework with int keys for User and Role
    // Identity provides secure password hashing and authentication out-of-the-box
    public class ApplicationDbContext : IdentityDbContext<User, ApplicationRole, int>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        // DbSets for application entities
        public DbSet<Property> Properties { get; set; }
        public DbSet<PropertyImage> PropertyImages { get; set; }
        public DbSet<Message> Messages { get; set; }
        public DbSet<Conversation> Conversations { get; set; }
        public DbSet<Favorite> Favorites { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            // OWASP A03: User entity configuration (additional to Identity defaults)
            modelBuilder.Entity<User>(entity =>
            {
                // OWASP A03: Database-level validation constraints
                entity.Property(u => u.FirstName).IsRequired().HasMaxLength(100);
                entity.Property(u => u.LastName).IsRequired().HasMaxLength(100);
                entity.Property(u => u.Address).HasMaxLength(255);
                entity.Property(u => u.Role).IsRequired();
                entity.Property(u => u.IsActive).HasDefaultValue(true);
                entity.Property(u => u.CreatedAt).IsRequired();
            });

            // OWASP A03 & A04: Property entity configuration
            modelBuilder.Entity<Property>(entity =>
            {
                entity.HasKey(p => p.Id);
                // OWASP A03: Input length constraints at database level
                entity.Property(p => p.Title).IsRequired().HasMaxLength(200);
                entity.Property(p => p.Description).HasMaxLength(1000);
                entity.Property(p => p.Price).HasColumnType("decimal(18,2)");

                // OWASP A01 & A04: Foreign key relationship with cascade delete
                // When a user is deleted, their properties are automatically deleted
                entity.HasOne(p => p.Owner)
                    .WithMany(u => u.Properties)
                    .HasForeignKey(p => p.OwnerId)
                    .OnDelete(DeleteBehavior.Cascade);

                // OWASP A04: Explicitly configure Images relationship
                entity.HasMany(p => p.Images)
                    .WithOne(pi => pi.Property)
                    .HasForeignKey(pi => pi.PropertyId)
                    .OnDelete(DeleteBehavior.Cascade);
            });

            // OWASP A03 & A04: PropertyImage entity configuration
            modelBuilder.Entity<PropertyImage>(entity =>
            {
                entity.HasKey(pi => pi.Id);
                // OWASP A03: Require image path
                entity.Property(pi => pi.ImagePath).IsRequired();
                entity.Property(pi => pi.UploadedAt).IsRequired();

                // OWASP A04: Configure inverse relationship with cascade delete
                entity.HasOne(pi => pi.Property)
                    .WithMany(p => p.Images)
                    .HasForeignKey(pi => pi.PropertyId)
                    .IsRequired()
                    .OnDelete(DeleteBehavior.Cascade);
            });

            // OWASP A03 & A04: Message entity configuration
            modelBuilder.Entity<Message>(entity =>
            {
                entity.HasKey(m => m.Id);
                // OWASP A03: Message content length constraint
                entity.Property(m => m.Content).IsRequired().HasMaxLength(1000);
                entity.Property(m => m.SentAt).IsRequired();

                // OWASP A04: Configure Sender relationship with Restrict delete
                // Prevents cascade delete conflicts - users can be deleted separately
                entity.HasOne(m => m.Sender)
                    .WithMany()
                    .HasForeignKey(m => m.SenderId)
                    .OnDelete(DeleteBehavior.Restrict);

                // OWASP A04: Configure Receiver relationship with Restrict delete
                entity.HasOne(m => m.Receiver)
                    .WithMany()
                    .HasForeignKey(m => m.ReceiverId)
                    .OnDelete(DeleteBehavior.Restrict);

                // OWASP A04: Configure Conversation relationship with cascade delete
                entity.HasOne(m => m.Conversation)
                    .WithMany(c => c.Messages)
                    .HasForeignKey(m => m.ConversationId)
                    .OnDelete(DeleteBehavior.Cascade);
            });

            // OWASP A03 & A04: Conversation entity configuration
            modelBuilder.Entity<Conversation>(entity =>
            {
                entity.HasKey(c => c.Id);

                // OWASP A04: Configure Seeker relationship with Restrict delete
                entity.HasOne(c => c.Seeker)
                    .WithMany()
                    .HasForeignKey(c => c.SeekerId)
                    .OnDelete(DeleteBehavior.Restrict);

                // OWASP A04: Configure Owner relationship with Restrict delete
                entity.HasOne(c => c.Owner)
                    .WithMany()
                    .HasForeignKey(c => c.OwnerId)
                    .OnDelete(DeleteBehavior.Restrict);

                // OWASP A04: Messages relationship (cascade delete configured above)
                entity.HasMany(c => c.Messages)
                    .WithOne(m => m.Conversation)
                    .HasForeignKey(m => m.ConversationId)
                    .OnDelete(DeleteBehavior.Cascade);
            });

            // OWASP A03 & A04: Favorite entity configuration
            modelBuilder.Entity<Favorite>(entity =>
            {
                entity.HasKey(f => f.Id);

                // OWASP A04: Composite unique index prevents duplicate favorites
                // Database-level constraint ensures data integrity
                entity.HasIndex(f => new { f.UserId, f.PropertyId }).IsUnique();

                // OWASP A04: Favorite belongs to one User with cascade delete
                entity.HasOne(f => f.User)
                    .WithMany(u => u.Favorites)
                    .HasForeignKey(f => f.UserId)
                    .OnDelete(DeleteBehavior.Cascade);

                // OWASP A04: Favorite belongs to one Property with Restrict delete
                // Prevents cascade delete conflicts with Property->User cascade
                entity.HasOne(f => f.Property)
                    .WithMany()
                    .HasForeignKey(f => f.PropertyId)
                    .OnDelete(DeleteBehavior.Restrict);
            });
        }
    }
}