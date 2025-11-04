// ========================================
// BaseController.cs
// ========================================
// Purpose: Base controller with secure user context retrieval
// OWASP Top 10 Security Implementations:
// - A01:2021 Broken Access Control: Centralized user authentication validation
// - A07:2021 Identification and Authentication Failures: Secure user ID extraction from claims

using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace CasaConnect.Controllers
{
    public class BaseController : Controller
    {
        // OWASP A01 & A07: Secure method to get authenticated user's ID
        // Validates user is authenticated and extracts user ID from claims
        protected int GetCurrentUserId()
        {
            // OWASP A01: Extract user identifier from authenticated claims
            var userIdClaim = User.FindFirstValue(ClaimTypes.NameIdentifier);

            // OWASP A07: Validate authentication state
            if (string.IsNullOrEmpty(userIdClaim))
            {
                throw new UnauthorizedAccessException("User is not authenticated");
            }

            // OWASP A03: Validate data type to prevent injection
            if (!int.TryParse(userIdClaim, out var userId))
            {
                throw new InvalidOperationException("Invalid user ID format");
            }

            return userId;
        }

        // OWASP A01 & A07: Safe method to get user ID without throwing exceptions
        // Useful for optional authentication scenarios
        protected int? GetCurrentUserIdOrNull()
        {
            // OWASP A01: Extract user identifier from claims
            var userIdClaim = User.FindFirstValue(ClaimTypes.NameIdentifier);

            // OWASP A07: Handle unauthenticated state gracefully
            if (string.IsNullOrEmpty(userIdClaim))
            {
                return null;
            }

            // OWASP A03: Validate data type
            if (int.TryParse(userIdClaim, out var userId))
            {
                return userId;
            }

            return null;
        }
    }
}