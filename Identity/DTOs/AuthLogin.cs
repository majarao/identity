using System.ComponentModel.DataAnnotations;

namespace Identity.DTOs;

public class AuthLogin
{
    [EmailAddress]
    [Required]
    public string Email { get; set; } = string.Empty;

    [Required]
    public string Password { get; set; } = string.Empty;
}
