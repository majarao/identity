using System.ComponentModel.DataAnnotations;

namespace Identity.DTOs;

public class UserCreate
{
    [Required]
    public string UserName { get; set; } = string.Empty;

    [EmailAddress]
    [Required]
    public string Email { get; set; } = string.Empty;

    [Required]
    public string Password { get; set; } = string.Empty;
}
