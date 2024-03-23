using Microsoft.AspNetCore.Identity;

namespace Identity.Entities;

public class User : IdentityUser
{
    public string? RefreshToken { get; set; }
    public DateTime? RefreshTokenExpiryTime { get; set; }
}
