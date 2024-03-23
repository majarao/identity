using Identity.Abstrations;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Identity.Services;

public class TokenService : ITokenService
{
    public JwtSecurityToken GenerateAccessToken(IEnumerable<Claim> claims, IConfiguration configuration)
    {
        string secretKey = configuration["JWT:SecretKey"]!;

        byte[] privateKey = Encoding.UTF8.GetBytes(secretKey);

        SigningCredentials signingCredentials = new(new SymmetricSecurityKey(privateKey), SecurityAlgorithms.HmacSha256Signature);

        _ = int.TryParse(configuration["JWT:RefreshTokenValidityInMinutes"], out int refreshTokenValidityInMinutes);

        SecurityTokenDescriptor tokenDescriptor = new()
        {
            Subject = new(claims),
            Expires = DateTime.UtcNow.AddMinutes(refreshTokenValidityInMinutes),
            Audience = configuration["JWT:ValidAudience"],
            Issuer = configuration["JWT:ValidIssuer"],
            SigningCredentials = signingCredentials
        };

        JwtSecurityTokenHandler tokenHandler = new();
        JwtSecurityToken token = tokenHandler.CreateJwtSecurityToken(tokenDescriptor);

        return token;
    }

    public string GenerateRefreshToken()
    {
        byte[] secureRandomBytes = new byte[128];

        using RandomNumberGenerator randomNumberGenerator = RandomNumberGenerator.Create();

        randomNumberGenerator.GetBytes(secureRandomBytes);

        string refreshToken = Convert.ToBase64String(secureRandomBytes);

        return refreshToken;
    }

    public ClaimsPrincipal GetPrincipalFromExpiredToken(string token, IConfiguration configuration)
    {
        string secretKey = configuration["JWT:SecretKey"]!;

        TokenValidationParameters tokenValidationParameters = new()
        {
            ValidateAudience = false,
            ValidateIssuer = false,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey)),
            ValidateLifetime = false
        };

        JwtSecurityTokenHandler tokenHandler = new();
        ClaimsPrincipal principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);

        if (securityToken is not JwtSecurityToken jwtSecurityToken ||
            !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
            throw new SecurityTokenException("Invalid token");

        return principal;
    }
}
