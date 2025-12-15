using Login.ApplictionDbContext;
using Login.Model;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Login.Services
{
    public class TokenService: ITokenService
    {
       
            private readonly IConfiguration _config;
            private readonly AppDbContext _db;
            private readonly UserManager<IdentityUser> _userManager;

            public TokenService(IConfiguration config, AppDbContext db, UserManager<IdentityUser> userManager)
            {
                _config = config;
                _db = db;
                _userManager = userManager;
            }

            public async Task<(string token, DateTime expires)> CreateAccessTokenAsync(IdentityUser user, IList<string> roles)
            {
                var jwtSection = _config.GetSection("Jwt");
                var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSection["Key"]!));
                var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

                var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id),
                new Claim(JwtRegisteredClaimNames.Email, user.Email ?? ""),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(ClaimTypes.NameIdentifier, user.Id)
            };
                claims.AddRange(roles.Select(r => new Claim(ClaimTypes.Role, r)));

                var expires = DateTime.UtcNow.AddMinutes(int.Parse(jwtSection["AccessTokenMinutes"]!));

                var token = new JwtSecurityToken(
                    issuer: jwtSection["Issuer"],
                    audience: jwtSection["Audience"],
                    claims: claims,
                    expires: expires,
                    signingCredentials: creds
                );

                var tokenString = new JwtSecurityTokenHandler().WriteToken(token);
                return (tokenString, expires);
            }

            public async Task<(string token, DateTime expires)> CreateRefreshTokenAsync(IdentityUser user)
            {
                var jwtSection = _config.GetSection("Jwt");
                var days = int.Parse(jwtSection["RefreshTokenDays"]!);

                // Cryptographically strong random token
                var token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
                var expires = DateTime.UtcNow.AddDays(days);

                var rt = new RefreshToken
                {
                    UserId = user.Id,
                    Token = token,
                    CreatedAt = DateTime.UtcNow,
                    ExpiresAt = expires,
                    Revoked = false
                };

                _db.RefreshTokens.Add(rt);
                await _db.SaveChangesAsync();

                return (token, expires);
            }

            public ClaimsPrincipal? GetPrincipalFromExpiredToken(string token)
            {
                var jwtSection = _config.GetSection("Jwt");
                var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSection["Key"]!));

                var tokenValidationParameters = new TokenValidationParameters
                {
                    ValidateAudience = true,
                    ValidateIssuer = true,
                    ValidateIssuerSigningKey = true,
                    ValidateLifetime = false, // ignore expiration here
                    ValidIssuer = jwtSection["Issuer"],
                    ValidAudience = jwtSection["Audience"],
                    IssuerSigningKey = key
                };

                var tokenHandler = new JwtSecurityTokenHandler();
                try
                {
                    var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out var securityToken);
                    if (securityToken is not JwtSecurityToken jwt ||
                        !jwt.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                    {
                        return null;
                    }
                    return principal;
                }
                catch
                {
                    return null;
                }
            }
        
    }
}
