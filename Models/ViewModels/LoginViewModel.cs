// Models/ViewModels/LoginViewModel.cs
// Purpose: Login form data validation
// OWASP Top 10 Security Implementations:
// - A03:2021 Injection: Input validation via Data Annotations
// - A07:2021 Identification and Authentication Failures: Email format validation, password requirements

using System.ComponentModel.DataAnnotations;

public class LoginViewModel
{
    // OWASP A03: Email format validation prevents malformed input
    // OWASP A07: Required field ensures authentication data is complete
    [Required(ErrorMessage = "Email is required")]
    [EmailAddress(ErrorMessage = "Invalid email format")]
    [StringLength(256, ErrorMessage = "Email cannot exceed 256 characters")]
    public string Email { get; set; }

    // OWASP A02: DataType.Password ensures password fields are masked in UI
    // OWASP A03: Length validation prevents excessively long input
    [Required(ErrorMessage = "Password is required")]
    [DataType(DataType.Password)]
    [StringLength(100, MinimumLength = 8, ErrorMessage = "Password must be between 8 and 100 characters")]
    public string Password { get; set; }

    // OWASP A07: RememberMe flag for persistent authentication cookies
    public bool RememberMe { get; set; }
}