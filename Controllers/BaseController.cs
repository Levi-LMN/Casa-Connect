// ========================================
// BaseController.cs - CREATE THIS NEW FILE
// ========================================
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace CasaConnect.Controllers
{
    public class BaseController : Controller
    {
        protected int GetCurrentUserId()
        {
            var userIdClaim = User.FindFirstValue(ClaimTypes.NameIdentifier);

            if (string.IsNullOrEmpty(userIdClaim))
            {
                throw new UnauthorizedAccessException("User is not authenticated");
            }

            if (!int.TryParse(userIdClaim, out var userId))
            {
                throw new InvalidOperationException("Invalid user ID format");
            }

            return userId;
        }

        protected int? GetCurrentUserIdOrNull()
        {
            var userIdClaim = User.FindFirstValue(ClaimTypes.NameIdentifier);

            if (string.IsNullOrEmpty(userIdClaim))
            {
                return null;
            }

            if (int.TryParse(userIdClaim, out var userId))
            {
                return userId;
            }

            return null;
        }
    }
}