using Identity.Abstrations;
using Identity.DTOs;
using Identity.Entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace Identity.Controllers;

[Route("[controller]")]
[ApiController]
public class AuthController(
    ITokenService tokenService,
    UserManager<User> userManager,
    IConfiguration configuration) : ControllerBase
{
    private readonly ITokenService TokenService = tokenService;
    private readonly UserManager<User> UserManager = userManager;
    private readonly IConfiguration Configuration = configuration;

    [HttpPost("login")]
    public async Task<IActionResult> Login(AuthLogin authLogin)
    {
        User? user = await UserManager.FindByEmailAsync(authLogin.Email);

        if (user is null)
            return NotFound("User not found");

        if (!await UserManager.CheckPasswordAsync(user, authLogin.Password))
            return BadRequest("Invalid credential");

        IList<string> userRoles = await UserManager.GetRolesAsync(user);

        List<Claim> authClaims =
        [
            new(ClaimTypes.Name, user.UserName!),
            new(ClaimTypes.Email, user.Email!),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        ];

        foreach (string userRole in userRoles)
            authClaims.Add(new(ClaimTypes.Role, userRole));

        JwtSecurityToken token = TokenService.GenerateAccessToken(authClaims, Configuration);
        string refreshToken = TokenService.GenerateRefreshToken();
        int.TryParse(Configuration["JWT:RefreshTokenValidityInMinutes"], out int refreshTokenValidityInMinutes);

        user.RefreshToken = refreshToken;
        user.RefreshTokenExpiryTime = DateTime.Now.AddMinutes(refreshTokenValidityInMinutes);

        await UserManager.UpdateAsync(user);

        return Ok(new
        {
            Token = new JwtSecurityTokenHandler().WriteToken(token),
            RefreshToken = refreshToken,
            Expiration = token.ValidTo
        });
    }

    [Authorize(Policy = "User")]
    [HttpPost("refreshtoken")]
    public async Task<IActionResult> RefreshToken(AuthToken authToken)
    {
        if (authToken is null)
            return BadRequest("Invalid client request");

        string? accessToken = authToken.AccessToken ?? throw new ArgumentNullException(nameof(authToken));
        string? refreshToken = authToken.RefreshToken ?? throw new ArgumentNullException(nameof(authToken));

        ClaimsPrincipal principal = TokenService.GetPrincipalFromExpiredToken(accessToken!, Configuration);

        if (principal is null)
            return BadRequest("Invalid token");

        string email = principal.FindFirstValue(ClaimTypes.Email)!;
        User? user = await UserManager.FindByEmailAsync(email);

        if (user is null)
            return NotFound("User not found");

        if (user.RefreshToken != refreshToken || user.RefreshTokenExpiryTime <= DateTime.Now)
            return BadRequest("Invalid token");

        JwtSecurityToken newAccessToken = TokenService.GenerateAccessToken(principal.Claims.ToList(), Configuration);
        string newRefreshToken = TokenService.GenerateRefreshToken();

        user.RefreshToken = newRefreshToken;
        await UserManager.UpdateAsync(user);

        return Ok(new AuthRefreshToken()
        {
            AccessToken = new JwtSecurityTokenHandler().WriteToken(newAccessToken),
            RefreshToken = newRefreshToken
        });
    }

    [Authorize(Policy = "User")]
    [HttpPost("logout")]
    public async Task<IActionResult> Logout()
    {
        Request.Headers.TryGetValue("Authorization", out StringValues token);
        string? accessToken = token[0]![7..];

        if (accessToken.IsNullOrEmpty())
            return BadRequest("Invalid token");

        ClaimsPrincipal principal = TokenService.GetPrincipalFromExpiredToken(accessToken!, Configuration);

        if (principal is null)
            return BadRequest("Invalid token");

        string email = principal.FindFirstValue(ClaimTypes.Email)!;
        User? user = await UserManager.FindByEmailAsync(email);

        if (user is null)
            return NotFound("User not found");

        user.RefreshToken = null;
        user.RefreshTokenExpiryTime = null;

        await UserManager.UpdateAsync(user);

        return Ok();
    }

    [Authorize(Policy = "Admin")]
    [HttpPost("revoke")]
    public async Task<IActionResult> Revoke(AuthRevoke authRevoke)
    {
        User? user = await UserManager.FindByEmailAsync(authRevoke.Email);

        if (user is null)
            return NotFound("User not found");

        user.RefreshToken = null;
        user.RefreshTokenExpiryTime = null;

        await UserManager.UpdateAsync(user);

        return Ok();
    }
}
