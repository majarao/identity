using System.ComponentModel.DataAnnotations;

namespace Identity.DTOs;

public class AuthRevoke
{
    [Required]
    [EmailAddress]
    public string Email { get; set; } = string.Empty;
}
