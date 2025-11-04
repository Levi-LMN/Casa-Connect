using Microsoft.AspNetCore.Identity;

namespace CasaConnect.Models
{
    // Custom role class that uses int as the primary key to match User
    public class ApplicationRole : IdentityRole<int>
    {
        public ApplicationRole() : base()
        {
        }

        public ApplicationRole(string roleName) : base(roleName)
        {
        }
    }
}