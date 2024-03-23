using System.ComponentModel.DataAnnotations;

namespace Identity.DTOs;

public class UserRolesCreate
{
    [EmailAddress]
    [Required]
    public string Email { get; set; } = string.Empty;

    [Required]
    public string RoleName { get; set; } = string.Empty;
}
